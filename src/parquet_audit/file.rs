//! One isolated, streaming Parquet audit. Only locally regenerated files can leave this stage.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use parquet::arrow::arrow_reader::{ArrowReaderOptions, ParquetRecordBatchReaderBuilder};
use parquet::arrow::arrow_writer::ArrowWriterOptions;
use parquet::arrow::{ArrowWriter, ProjectionMask};
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};

use super::{atomic_json, finding_error, infrastructure, profile, validation};
use crate::abort::{Result, abort, infra};
use crate::clickhouse::ddl::parse_create_table;
use crate::models::Overrides;

#[derive(Clone, Serialize, Deserialize)]
pub struct Job {
    pub input: PathBuf,
    pub work: PathBuf,
    pub ddl: String,
    #[serde(default)]
    pub native_policy: Option<super::policy::TablePolicy>,
    #[serde(default)]
    pub stop_path: Option<PathBuf>,
    pub overrides: Overrides,
    pub source_object: String,
    pub batch: String,
    pub imported_at: String,
    pub file_index: u32,
    pub survey: bool,
    pub batch_rows: usize,
    pub row_group_bytes: u64,
    pub chunk_bytes: u64,
    pub memory_bytes: u64,
    pub output_budget: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Output {
    pub name: String,
    pub bytes: u64,
    pub rows: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checked {
    pub input_sha256: String,
    pub rows: u64,
    pub schema: arrow_schema::Schema,
    pub input_schema: arrow_schema::Schema,
    pub outputs: Vec<Output>,
    pub findings: u64,
    pub findings_by_reason: BTreeMap<String, u64>,
    pub finding_rows_by_column: BTreeMap<String, BTreeMap<String, u64>>,
    pub field_audits: Vec<validation::FieldAudit>,
    pub profile: profile::Summary,
    pub elapsed_secs: f64,
}

/// Enforce output reservations *during writes*, including parquet footer/metadata overhead.
struct QuotaWriter {
    file: File,
    used: Arc<Mutex<u64>>,
    cap: u64,
}
impl Write for QuotaWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut used = self
            .used
            .lock()
            .map_err(|_| std::io::Error::other("scratch accounting poisoned"))?;
        if bytes.len() as u64 > self.cap.saturating_sub(*used) {
            return Err(std::io::Error::other(
                "per-file scratch reservation exhausted; increase day scratch budget",
            ));
        }
        let n = self.file.write(bytes)?;
        *used += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

pub fn hash_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = File::open(path).map_err(infrastructure)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(infrastructure)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn check(job: &Job) -> Result<Checked> {
    if job.stop_path.as_ref().is_some_and(|p| p.exists()) {
        return abort("run stopped before validation");
    }
    let started = Instant::now();
    let limits = &job.overrides.limits;
    std::fs::create_dir_all(&job.work).map_err(infrastructure)?;
    let mut input = File::open(&job.input).map_err(infrastructure)?;
    let size = input.metadata().map_err(infrastructure)?.len();
    if size < 12 || size > limits.max_compressed_bytes {
        return abort("Parquet object exceeds compressed size cap or is truncated");
    }
    // Bound footer reads before the library's metadata parser allocates. Worker address-space
    // limits are a second boundary for lying page headers and allocation amplification.
    input.seek(SeekFrom::End(-8)).map_err(infrastructure)?;
    let mut footer = [0u8; 8];
    input.read_exact(&mut footer).map_err(infrastructure)?;
    let footer_len = u32::from_le_bytes(footer[..4].try_into().unwrap()) as u64;
    if &footer[4..] != b"PAR1"
        || footer_len > size - 12
        || footer_len > (8 * 1024 * 1024).min(job.memory_bytes / 32)
    {
        return abort("invalid or oversized Parquet footer");
    }
    input.seek(SeekFrom::Start(0)).map_err(infrastructure)?;
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic).map_err(infrastructure)?;
    if &magic != b"PAR1" {
        return abort("invalid Parquet magic");
    }
    let input_sha256 = hash_file(&job.input)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new_with_options(
        input,
        ArrowReaderOptions::new().with_skip_arrow_metadata(true),
    )
    .map_err(finding_error)?;
    let metadata = builder.metadata();
    let expected_rows =
        u64::try_from(metadata.file_metadata().num_rows()).map_err(finding_error)?;
    if expected_rows > limits.max_rows_per_page {
        return abort("Parquet object exceeds pinned row cap");
    }
    let mut uncompressed = 0u64;
    let mut row_count = 0u64;
    for group in metadata.row_groups() {
        let group_bytes = u64::try_from(group.total_byte_size()).map_err(finding_error)?;
        uncompressed = uncompressed
            .checked_add(group_bytes)
            .ok_or_else(|| abort::<()>("Parquet size overflow").unwrap_err())?;
        row_count = row_count
            .checked_add(u64::try_from(group.num_rows()).map_err(finding_error)?)
            .ok_or_else(|| abort::<()>("Parquet row count overflow").unwrap_err())?;
        if group_bytes > job.memory_bytes / 4 {
            return infra("row group exceeds worker decoding reservation; increase worker memory");
        }
        for col in group.columns() {
            if col.file_path().is_some() {
                return abort("external Parquet column chunks are forbidden");
            }
            let (offset, length) = col.byte_range();
            if offset < 4
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > size - footer_len - 8)
            {
                return abort("Parquet column chunk lies outside data region");
            }
        }
    }
    if row_count != expected_rows {
        return abort("Parquet row-group counts disagree with footer");
    }
    if uncompressed > limits.max_uncompressed_bytes {
        return abort("Parquet object exceeds pinned uncompressed cap");
    }
    crate::limits::Limits::check_ratio(
        size,
        uncompressed,
        limits.max_expansion_ratio,
        "Parquet expansion",
    )?;
    let contract = if let Some(native) = &job.native_policy {
        validation::build_native(native, &job.overrides, builder.schema())?
    } else {
        let ddl = parse_create_table(&job.ddl)?;
        validation::build(&ddl, &job.overrides, builder.schema())?
    };
    check_narrow_physical_integers(job, builder.parquet_schema(), &contract.kept)?;
    // Read only kept columns, but validate the complete source schema first.
    let projection = ProjectionMask::roots(builder.parquet_schema(), contract.kept.iter().copied());
    let input_schema = builder.schema().clone();
    // Projection follows source order, while output follows pinned order. Rebuild the contract
    // against an ordered full batch below by retaining original positions.
    let mut projected_indices = contract.kept.clone();
    projected_indices.sort_unstable();
    let reader = builder
        .with_projection(projection)
        .with_batch_size(job.batch_rows)
        .build()
        .map_err(finding_error)?;
    let mut profile = profile::Profile::new(
        contract
            .kept
            .iter()
            .map(|i| input_schema.field(*i).name().clone()),
    );
    let mut findings_file =
        File::create(job.work.join("findings.jsonl")).map_err(infrastructure)?;
    let mut findings = 0u64;
    let mut finding_samples_bytes = 0u64;
    let mut reasons = BTreeMap::new();
    let mut finding_rows_by_column: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut rows = 0u64;
    let mut outputs = Vec::new();
    let used = Arc::new(Mutex::new(0u64));
    let mut writer: Option<ArrowWriter<QuotaWriter>> = None;
    let mut chunk_rows = 0u64;
    let mut chunk_decoded = 0u64;
    let mut decoded = 0u64;
    for next in reader {
        if job.stop_path.as_ref().is_some_and(|p| p.exists()) {
            return abort("run stopped during validation");
        }
        if started.elapsed().as_secs() >= limits.wall_clock_secs {
            return infra("Parquet audit exceeded wall-clock budget");
        }
        let batch = next.map_err(finding_error)?;
        for array in batch.columns() {
            array.to_data().validate_full().map_err(finding_error)?;
        }
        let batch_bytes = batch.get_array_memory_size() as u64;
        if batch_bytes > job.memory_bytes / 4 {
            return infra(
                "decoded batch exceeds worker reservation; reduce batch rows or increase worker memory",
            );
        }
        decoded = decoded
            .checked_add(batch_bytes)
            .ok_or_else(|| abort::<()>("decoded byte counter overflow").unwrap_err())?;
        // Dictionary/slice buffers can be counted repeatedly; metadata and per-batch bounds are
        // the hostile-input limits. This counter is for output rotation, not source byte claims.
        let mut columns = Vec::with_capacity(input_schema.fields().len());
        for (i, f) in input_schema.fields().iter().enumerate() {
            columns.push(
                if let Some(at) = projected_indices.iter().position(|index| *index == i) {
                    batch.column(at).clone()
                } else {
                    arrow_array::new_null_array(f.data_type(), batch.num_rows())
                },
            );
        }
        // Dropped non-nullable columns are placeholders only and never checked or forwarded.
        let full_schema = Arc::new(arrow_schema::Schema::new(
            input_schema
                .fields()
                .iter()
                .map(|f| f.as_ref().clone().with_nullable(true))
                .collect::<Vec<_>>(),
        ));
        let full = RecordBatch::try_new(full_schema, columns).map_err(finding_error)?;
        for at in 0..full.num_rows() {
            let row = rows + at as u64 + 1;
            let mut seen_findings = std::collections::BTreeSet::new();
            contract.check_row(&full, at, limits, job.file_index, row, &mut |finding| {
                findings += 1;
                if let Some(column) = &finding.column
                    && seen_findings.insert((column.clone(), finding.reason.clone()))
                {
                    *finding_rows_by_column
                        .entry(column.clone())
                        .or_default()
                        .entry(finding.reason.clone())
                        .or_default() += 1;
                }
                *reasons.entry(finding.reason.clone()).or_insert(0u64) += 1;
                let sample = serde_json::to_vec(&finding).map_err(infrastructure)?;
                // Exact aggregate counts survive; diagnostic samples cannot exhaust day scratch.
                if finding_samples_bytes + (sample.len() as u64) < 1024 * 1024 {
                    findings_file.write_all(&sample).map_err(infrastructure)?;
                    findings_file.write_all(b"\n").map_err(infrastructure)?;
                    finding_samples_bytes += sample.len() as u64 + 1;
                }
                if !job.survey || job.native_policy.is_some() {
                    findings_file.flush().map_err(infrastructure)?;
                    if let Some(path) = &job.stop_path {
                        super::stop::persist(path, &finding.reason)?;
                    }
                    return abort("native Parquet field audit found a violation");
                }
                Ok(())
            })?;
        }
        profile.add(&full, &contract.kept)?;
        rows += full.num_rows() as u64;
        if rows > expected_rows {
            return abort("decoded rows exceed Parquet footer count");
        }
        if !job.survey {
            if writer.is_none() {
                writer = Some(new_writer(
                    job,
                    outputs.len(),
                    contract.schema.clone(),
                    used.clone(),
                )?);
            }
            let mut arrays: Vec<ArrayRef> = contract
                .kept
                .iter()
                .map(|index| full.column(*index).clone())
                .collect();
            for literal in [&job.source_object, &job.batch, &job.imported_at] {
                arrays.push(Arc::new(StringArray::from_iter_values(
                    std::iter::repeat_n(literal.as_str(), full.num_rows()),
                )));
            }
            let output =
                RecordBatch::try_new(contract.schema.clone(), arrays).map_err(finding_error)?;
            let w = writer.as_mut().unwrap();
            // Reserve room for the batch before handing it to the encoder.
            if w.memory_size() as u64 + output.get_array_memory_size() as u64 > job.memory_bytes / 2
            {
                w.flush().map_err(infrastructure)?;
            }
            w.write(&output).map_err(infrastructure)?;
            chunk_rows += output.num_rows() as u64;
            chunk_decoded += output.get_array_memory_size() as u64;
            if w.in_progress_size() as u64 >= job.row_group_bytes
                || w.memory_size() as u64 >= job.memory_bytes / 4
            {
                w.flush().map_err(infrastructure)?;
            }
            if chunk_decoded >= job.chunk_bytes {
                finish_chunk(job, writer.take().unwrap(), chunk_rows, &mut outputs)?;
                chunk_rows = 0;
                chunk_decoded = 0;
            }
        }
    }
    if rows != expected_rows {
        return abort("decoded row count differs from Parquet footer");
    }
    if !job.survey {
        // Preserve an empty input as a valid, schema-bearing Parquet file.
        if writer.is_none() && outputs.is_empty() {
            writer = Some(new_writer(job, 0, contract.schema.clone(), used)?);
        }
        if let Some(writer) = writer {
            finish_chunk(job, writer, chunk_rows, &mut outputs)?;
        }
    }
    findings_file.sync_all().map_err(infrastructure)?;
    let checked = Checked {
        input_schema: validation::clean_schema(&input_schema),
        field_audits: contract.field_audits(),
        finding_rows_by_column,
        input_sha256,
        rows,
        schema: contract.schema.as_ref().clone(),
        outputs,
        findings,
        findings_by_reason: reasons,
        profile: profile.finish(),
        elapsed_secs: started.elapsed().as_secs_f64(),
    };
    atomic_json(&job.work.join("checked.json"), &checked)?;
    tracing::info!(
        rows,
        decoded_bytes = decoded,
        seconds = checked.elapsed_secs,
        "Parquet file checked"
    );
    Ok(checked)
}

fn new_writer(
    job: &Job,
    index: usize,
    schema: Arc<arrow_schema::Schema>,
    used: Arc<Mutex<u64>>,
) -> Result<ArrowWriter<QuotaWriter>> {
    if index >= 10_000 {
        return infra("source file exceeds 10000 output chunks; increase output chunk bytes");
    }
    let path = job.work.join(format!("part-{index:06}.parquet.partial"));
    let file = File::create(path).map_err(infrastructure)?;
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(
            ZstdLevel::try_new(1).map_err(infrastructure)?,
        ))
        .set_max_row_group_size(job.batch_rows.saturating_mul(16))
        .set_write_batch_size(1024)
        .set_created_by("salvage native Parquet audit v1".into())
        .build();
    ArrowWriter::try_new_with_options(
        QuotaWriter {
            file,
            used,
            cap: job.output_budget,
        },
        schema,
        ArrowWriterOptions::new()
            .with_properties(props)
            .with_skip_arrow_metadata(true),
    )
    .map_err(infrastructure)
}

fn finish_chunk(
    job: &Job,
    writer: ArrowWriter<QuotaWriter>,
    rows: u64,
    outputs: &mut Vec<Output>,
) -> Result<()> {
    let name = format!("part-{:06}.parquet", outputs.len());
    writer.close().map_err(infrastructure)?;
    let partial = job.work.join(format!("{name}.partial"));
    File::open(&partial)
        .map_err(infrastructure)?
        .sync_all()
        .map_err(infrastructure)?;
    let bytes = std::fs::metadata(&partial).map_err(infrastructure)?.len();
    let sha256 = hash_file(&partial)?;
    std::fs::rename(partial, job.work.join(&name)).map_err(infrastructure)?;
    outputs.push(Output {
        name,
        bytes,
        rows,
        sha256,
    });
    Ok(())
}

/// Arrow's INT32 -> Int8/Int16/UInt8/UInt16 adapter uses Rust `as` casts. Validate
/// physical values first so a malformed logical annotation cannot silently wrap them.
fn check_narrow_physical_integers(
    job: &Job,
    schema: &parquet::schema::types::SchemaDescriptor,
    kept: &[usize],
) -> Result<()> {
    use parquet::basic::LogicalType;
    use parquet::column::reader::ColumnReader;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    let mut columns = Vec::new();
    for (index, column) in schema.columns().iter().enumerate() {
        if !kept.contains(&schema.get_column_root_idx(index)) {
            continue;
        }
        let bounds = match column.logical_type() {
            Some(LogicalType::Integer {
                bit_width: 8,
                is_signed: true,
            }) => Some((-128, 127)),
            Some(LogicalType::Integer {
                bit_width: 16,
                is_signed: true,
            }) => Some((-32768, 32767)),
            Some(LogicalType::Integer {
                bit_width: 8,
                is_signed: false,
            }) => Some((0, 255)),
            Some(LogicalType::Integer {
                bit_width: 16,
                is_signed: false,
            }) => Some((0, 65535)),
            _ => None,
        };
        // Legacy converted types carry the same narrowing semantics.
        let bounds = bounds.or_else(|| match column.converted_type() {
            parquet::basic::ConvertedType::INT_8 => Some((-128, 127)),
            parquet::basic::ConvertedType::INT_16 => Some((-32768, 32767)),
            parquet::basic::ConvertedType::UINT_8 => Some((0, 255)),
            parquet::basic::ConvertedType::UINT_16 => Some((0, 65535)),
            _ => None,
        });
        if let Some(bounds) = bounds {
            columns.push((index, bounds));
        }
    }
    if columns.is_empty() {
        return Ok(());
    }
    let reader = SerializedFileReader::new(File::open(&job.input).map_err(infrastructure)?)
        .map_err(finding_error)?;
    for group in 0..reader.num_row_groups() {
        let group = reader.get_row_group(group).map_err(finding_error)?;
        for (column, (min, max)) in &columns {
            let ColumnReader::Int32ColumnReader(mut column) =
                group.get_column_reader(*column).map_err(finding_error)?
            else {
                return abort("narrow integer has incompatible physical representation");
            };
            let mut values = Vec::new();
            let mut definitions = Vec::new();
            let mut repetitions = Vec::new();
            loop {
                if job.stop_path.as_ref().is_some_and(|p| p.exists()) {
                    return abort("run stopped during physical type validation");
                }
                values.clear();
                definitions.clear();
                repetitions.clear();
                let (records, _, _) = column
                    .read_records(
                        job.batch_rows,
                        Some(&mut definitions),
                        Some(&mut repetitions),
                        &mut values,
                    )
                    .map_err(finding_error)?;
                if values.iter().any(|v| v < min || v > max) {
                    return abort(
                        "physical Parquet integer exceeds its declared logical type range",
                    );
                }
                if records == 0 {
                    break;
                }
            }
        }
    }
    Ok(())
}

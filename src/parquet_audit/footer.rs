//! Open a Parquet footer, correcting one named writer defect before the schema is built.
//!
//! ClickHouse before the fix in [PR 75029] wrote every `DateTime64(9)` column with logical type
//! `Timestamp(NANOS)` **and** legacy converted type `UTF8` ([issue 74988]). The two contradict
//! each other -- no converted type exists for nanosecond timestamps, and `UTF8` may only annotate
//! a `BYTE_ARRAY` -- and parquet-rs refuses to build the schema, so the file cannot be read at
//! all, let alone audited. The fixed writer emits converted type `NONE`.
//!
//! With `--accept-clickhouse-74988` this does what the fixed writer would have done: for a column
//! matching **exactly** that signature, the converted type is cleared before the schema is built.
//! Nothing else in the footer and no value in the file is touched, the column is named in the
//! partition's manifest under `footer_corrections`, and a footer that is wrong in any other way
//! is still refused. Without the flag, such a file is refused with a message naming it.
//!
//! [issue 74988]: https://github.com/ClickHouse/ClickHouse/issues/74988
//! [PR 75029]: https://github.com/ClickHouse/ClickHouse/pull/75029
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;

use parquet::arrow::arrow_reader::{
    ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder,
};
use parquet::basic::ColumnOrder;
use parquet::file::metadata::{FileMetaData, ParquetMetaData, RowGroupMetaData};
use parquet::format::{ConvertedType, LogicalType, TimeUnit};
use parquet::schema::types::{SchemaDescriptor, from_thrift};
use parquet::thrift::TSerializable;
use thrift::protocol::TCompactInputProtocol;

use crate::abort::{Result, SalvageError, abort};

/// The footer's byte range, as the caller has already validated it: `[start, start + len)`.
pub struct Footer {
    pub start: u64,
    pub len: u64,
}

/// Build the reader. `accept_ch74988` selects the correcting path; without it the file goes
/// through parquet's own reader untouched, exactly as before this module existed.
pub fn open(
    mut input: File,
    footer: &Footer,
    accept_ch74988: bool,
) -> Result<(ParquetRecordBatchReaderBuilder<File>, Vec<String>)> {
    let options = ArrowReaderOptions::new().with_skip_arrow_metadata(true);
    if !accept_ch74988 {
        let builder = ParquetRecordBatchReaderBuilder::try_new_with_options(input, options)
            .map_err(refuse_or_finding)?;
        return Ok((builder, Vec::new()));
    }
    input
        .seek(SeekFrom::Start(footer.start))
        .map_err(super::infrastructure)?;
    let mut bytes = vec![0u8; usize::try_from(footer.len).map_err(super::infrastructure)?];
    input
        .read_exact(&mut bytes)
        .map_err(super::infrastructure)?;
    let (metadata, corrections) = decode(&bytes)?;
    let metadata = ArrowReaderMetadata::try_new(Arc::new(metadata), options).map_err(|e| {
        abort::<()>("invalid Parquet schema")
            .unwrap_err()
            .with("error", e)
    })?;
    Ok((
        ParquetRecordBatchReaderBuilder::new_with_metadata(input, metadata),
        corrections,
    ))
}

/// A parquet-rs schema refusal that is the #74988 signature gets a message that says what to do;
/// anything else stays the opaque finding it always was.
fn refuse_or_finding(e: parquet::errors::ParquetError) -> SalvageError {
    let text = e.to_string();
    if text.contains("Logical type Timestamp") && text.contains("converted type UTF8") {
        abort::<()>(
            "footer carries ClickHouse issue 74988 (Timestamp(NANOS) with converted type UTF8); \
             pass --accept-clickhouse-74988 to read it with that one field corrected",
        )
        .unwrap_err()
        .with("error", text)
    } else {
        super::finding_error(e)
    }
}

/// Mirror of `ParquetMetaDataReader::decode_metadata`, with the correction applied to the thrift
/// schema before any of parquet-rs's validation sees it.
fn decode(bytes: &[u8]) -> Result<(ParquetMetaData, Vec<String>)> {
    let mut protocol = TCompactInputProtocol::new(Cursor::new(bytes));
    let mut thrift_metadata = parquet::format::FileMetaData::read_from_in_protocol(&mut protocol)
        .map_err(|e| {
        abort::<()>("invalid Parquet footer")
            .unwrap_err()
            .with("error", e)
    })?;
    let mut corrections = Vec::new();
    for element in &mut thrift_metadata.schema {
        let nanos_timestamp = matches!(
            &element.logical_type,
            Some(LogicalType::TIMESTAMP(t)) if matches!(t.unit, TimeUnit::NANOS(_))
        );
        if nanos_timestamp && element.converted_type == Some(ConvertedType::UTF8) {
            element.converted_type = None;
            corrections.push(element.name.clone());
        }
    }
    let schema = from_thrift(&thrift_metadata.schema).map_err(|e| {
        abort::<()>("invalid Parquet schema")
            .unwrap_err()
            .with("error", e)
    })?;
    let descriptor = Arc::new(SchemaDescriptor::new(schema));
    let mut row_groups = Vec::with_capacity(thrift_metadata.row_groups.len());
    for group in thrift_metadata.row_groups {
        row_groups.push(
            RowGroupMetaData::from_thrift(descriptor.clone(), group).map_err(|e| {
                abort::<()>("invalid Parquet row group")
                    .unwrap_err()
                    .with("error", e)
            })?,
        );
    }
    let column_orders = match thrift_metadata.column_orders {
        None => None,
        Some(orders) => {
            if orders.len() != descriptor.num_columns() {
                return abort("Parquet column order length mismatch");
            }
            Some(
                descriptor
                    .columns()
                    .iter()
                    .map(|column| {
                        ColumnOrder::TYPE_DEFINED_ORDER(ColumnOrder::get_sort_order(
                            column.logical_type(),
                            column.converted_type(),
                            column.physical_type(),
                        ))
                    })
                    .collect(),
            )
        }
    };
    let file_metadata = FileMetaData::new(
        thrift_metadata.version,
        thrift_metadata.num_rows,
        thrift_metadata.created_by,
        thrift_metadata.key_value_metadata,
        descriptor,
        column_orders,
    );
    if corrections.is_empty() {
        // The flag was passed but nothing needed it. Not an error, but worth a line: the operator
        // believed this source carried the defect.
        tracing::info!("--accept-clickhouse-74988 set; this footer needed no correction");
    }
    Ok((ParquetMetaData::new(file_metadata, row_groups), corrections))
}

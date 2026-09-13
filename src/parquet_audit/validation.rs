//! Native-value adapter to the existing bounds and injection audit. No TSV serialization.
use std::sync::Arc;

use arrow_array::*;
use arrow_schema::{DataType, Field as ArrowField, Schema, TimeUnit};
use regex::bytes::Regex;

use crate::abort::{Result, SalvageError, abort, usage};
use crate::audit::{bounds, payloads};
use crate::clickhouse::ddl::PinnedDdl;
use crate::clickhouse::tsv::Field;
use crate::clickhouse::types::{ClickHouseType as Ch, FloatWidth, Validator, rules_for};
use crate::limits::Limits;
use crate::models::{ColumnOverride, Finding, FreedomClass, Overrides};

pub struct Contract {
    pub kept: Vec<usize>,
    nodes: Vec<Node>,
    pub schema: Arc<Schema>,
}

struct Node {
    name: String,
    ty: Ch,
    nullable: bool,
    scalar: Option<bounds::ColumnContract>,
    pattern: Option<&'static Regex>,
    children: Vec<Node>,
}

fn inner(ty: &Ch) -> (&Ch, bool) {
    match ty {
        Ch::Nullable(t) => (inner(t).0, true),
        Ch::LowCardinality(t) => inner(t),
        _ => (ty, false),
    }
}

pub fn build(ddl: &PinnedDdl, overrides: &Overrides, schema: &Schema) -> Result<Contract> {
    if schema.fields().len() != ddl.columns.len() {
        return abort("Parquet column count differs from pinned DDL");
    }
    if schema.fields().len() > overrides.limits.max_fields_per_row as usize {
        return abort("Parquet schema exceeds the pinned column cap");
    }
    let mut kept = Vec::new();
    let mut nodes = Vec::new();
    let mut fields = Vec::new();
    for column in &ddl.columns {
        let name = column.name.as_str();
        if crate::clickhouse::quarantine::PROVENANCE_COLUMNS
            .iter()
            .any(|(n, _)| *n == name)
        {
            return usage("source column collides with audit provenance");
        }
        let positions: Vec<_> = schema
            .fields()
            .iter()
            .enumerate()
            .filter(|(_, f)| f.name() == name)
            .collect();
        if positions.len() != 1 {
            return abort("Parquet column missing or duplicated")
                .map_err(|e: SalvageError| e.with("column", name));
        }
        let (index, field) = positions[0];
        let over = overrides.columns.get(name);
        // Even excluded columns must be accounted for by the pinned schema. Their values are
        // deliberately not parsed or forwarded, matching the existing column-drop contract.
        let node = Node::build(
            name.to_owned(),
            &column.ty,
            field.data_type(),
            over,
            &overrides.limits,
        )?;
        if over.is_some_and(|o| o.drop) {
            continue;
        }
        kept.push(index);
        nodes.push(node);
        fields.push(clean_field(field));
    }
    if kept.is_empty() {
        return usage("every column is dropped");
    }
    for (name, _) in crate::clickhouse::quarantine::PROVENANCE_COLUMNS {
        fields.push(ArrowField::new(*name, DataType::Utf8, false));
    }
    Ok(Contract {
        kept,
        nodes,
        schema: Arc::new(Schema::new(fields)),
    })
}

// Source Arrow/key-value metadata is never inherited by the regenerated file, including on
// nested fields. Physical/logical types remain native.
fn clean_field(field: &ArrowField) -> ArrowField {
    let dt = match field.data_type() {
        DataType::List(f) => DataType::List(Arc::new(clean_field(f))),
        DataType::LargeList(f) => DataType::LargeList(Arc::new(clean_field(f))),
        DataType::Struct(fs) => DataType::Struct(fs.iter().map(|f| clean_field(f)).collect()),
        DataType::Map(f, sorted) => DataType::Map(Arc::new(clean_field(f)), *sorted),
        other => other.clone(),
    };
    ArrowField::new(field.name(), dt, field.is_nullable())
}

impl Node {
    fn build(
        name: String,
        ty: &Ch,
        dt: &DataType,
        over: Option<&ColumnOverride>,
        limits: &Limits,
    ) -> Result<Self> {
        if ty.depth() > limits.max_nesting_depth {
            return usage("pinned type exceeds nesting cap");
        }
        let (ty, nullable) = inner(ty);
        let mut children = Vec::new();
        let matches = match (ty, dt) {
            (Ch::UInt(w), d) => matches!(
                (w.bits(), d),
                (8, DataType::UInt8)
                    | (16, DataType::UInt16)
                    | (32, DataType::UInt32)
                    | (64, DataType::UInt64)
            ),
            (Ch::Int(w), d) => matches!(
                (w.bits(), d),
                (8, DataType::Int8)
                    | (16, DataType::Int16)
                    | (32, DataType::Int32)
                    | (64, DataType::Int64)
            ),
            (Ch::Float(FloatWidth::F32), DataType::Float32)
            | (Ch::Float(FloatWidth::F64), DataType::Float64)
            | (Ch::Bool, DataType::Boolean) => true,
            (
                Ch::Decimal { p, s },
                DataType::Decimal128(ap, as_) | DataType::Decimal256(ap, as_),
            ) => *p == u32::from(*ap) && i32::try_from(*s).ok() == Some(i32::from(*as_)),
            (
                Ch::String,
                DataType::Utf8 | DataType::LargeUtf8 | DataType::Binary | DataType::LargeBinary,
            ) => true,
            (
                Ch::FixedString(_),
                DataType::Binary | DataType::LargeBinary | DataType::FixedSizeBinary(_),
            ) => true,
            (Ch::Date | Ch::Date32, DataType::Date32) => true,
            (Ch::DateTime | Ch::DateTime64 { .. }, DataType::Timestamp(_, tz)) => {
                tz.as_deref().is_none_or(|z| z == "UTC" || z == "+00:00")
            }
            (
                Ch::Uuid | Ch::Ipv6,
                DataType::Utf8
                | DataType::LargeUtf8
                | DataType::Binary
                | DataType::FixedSizeBinary(16),
            ) => true,
            (Ch::Ipv4, DataType::UInt32 | DataType::Utf8 | DataType::LargeUtf8) => true,
            (
                Ch::Enum8(_),
                DataType::Int8 | DataType::Int16 | DataType::Utf8 | DataType::LargeUtf8,
            )
            | (Ch::Enum16(_), DataType::Int16 | DataType::Utf8 | DataType::LargeUtf8) => true,
            (Ch::Array(child), DataType::List(f) | DataType::LargeList(f)) => {
                children.push(Self::build(
                    format!("{name}[]"),
                    child,
                    f.data_type(),
                    over,
                    limits,
                )?);
                true
            }
            (Ch::Tuple(types), DataType::Struct(fs)) if types.len() == fs.len() => {
                for (i, (t, f)) in types.iter().zip(fs).enumerate() {
                    children.push(Self::build(
                        format!("{name}.{}", i + 1),
                        t,
                        f.data_type(),
                        over,
                        limits,
                    )?);
                }
                true
            }
            (Ch::Map(k, v), DataType::Map(entries, _)) => {
                if let DataType::Struct(fs) = entries.data_type() {
                    if fs.len() != 2 {
                        false
                    } else {
                        children.push(Self::build(
                            format!("{name}.keys"),
                            k,
                            fs[0].data_type(),
                            over,
                            limits,
                        )?);
                        children.push(Self::build(
                            format!("{name}.values"),
                            v,
                            fs[1].data_type(),
                            over,
                            limits,
                        )?);
                        true
                    }
                } else {
                    false
                }
            }
            (Ch::Nested(types), DataType::List(f) | DataType::LargeList(f)) => {
                if let DataType::Struct(fs) = f.data_type() {
                    if types.len() != fs.len() {
                        false
                    } else {
                        for ((n, t), f) in types.iter().zip(fs) {
                            if n.as_str() != f.name() {
                                return abort("Nested field name differs from pinned DDL");
                            }
                            children.push(Self::build(
                                format!("{name}.{}", n.as_str()),
                                t,
                                f.data_type(),
                                over,
                                limits,
                            )?);
                        }
                        true
                    }
                } else {
                    false
                }
            }
            _ => false,
        };
        if !matches {
            return abort(
                "Parquet logical type differs from or cannot represent pinned ClickHouse type",
            )
            .map_err(|e: SalvageError| {
                e.with("column", &name)
                    .with("expected", ty.canonical())
                    .with("actual", dt)
            });
        }
        let scalar = if children.is_empty() {
            let mut rules = rules_for(ty, limits.max_array_elements)?;
            if over.is_some_and(|o| o.hex) {
                crate::clickhouse::types::apply_hex_override(ty, &mut rules)?;
            }
            let mut validator = rules.columns.remove(0).validator;
            if let (Validator::EnumId { ids }, Some(explicit)) =
                (&mut validator, over.and_then(|o| o.enum_ids.as_ref()))
            {
                if explicit.iter().any(|id| !ids.contains(id)) {
                    return usage("enum override contains an id absent from pinned DDL");
                }
                *ids = explicit.clone();
            }
            Some(bounds::ColumnContract {
                name: name.clone(),
                source: name.clone(),
                nullable,
                class: over.map_or(FreedomClass::Closed, |o| o.class),
                validator,
                max_len: over.and_then(|o| o.max_len),
                pattern: over.and_then(|o| o.pattern.clone()),
                equal_length_group: false,
            })
        } else {
            None
        };
        let pattern = scalar
            .as_ref()
            .map(bounds::prepare_pattern)
            .transpose()?
            .flatten();
        Ok(Self {
            name,
            ty: ty.clone(),
            nullable,
            scalar,
            pattern,
            children,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn check(
        &self,
        array: &dyn Array,
        at: usize,
        limits: &Limits,
        file: u32,
        row: u64,
        remaining: &mut u64,
        emit: &mut impl FnMut(Finding) -> Result<()>,
    ) -> Result<()> {
        if array.is_null(at) {
            if !self.nullable {
                emit(self.finding(file, row, "NULL in a non-nullable column", &[]))?;
            }
            return Ok(());
        }
        if let Some(contract) = &self.scalar {
            let raw = match scalar_bytes(array, at, &self.ty) {
                Ok(raw) => raw,
                Err(e) => return emit(self.finding(file, row, e.reason(), &[])),
            };
            if raw.len() as u64 > *remaining {
                return emit(self.finding(file, row, "value exceeds pinned field byte cap", &raw));
            }
            *remaining -= raw.len() as u64;
            let is_hex = matches!(
                contract.validator,
                Validator::HexAny | Validator::HexExact { .. }
            ) && matches!(self.ty, Ch::String | Ch::FixedString(_));
            let value = if is_hex {
                hex(&raw).into_bytes()
            } else {
                raw.clone()
            };
            if let Some(finding) = bounds::check_value_precompiled(
                contract,
                &Field::Value(value),
                limits,
                file,
                row,
                self.pattern,
            )? {
                emit(finding)?;
            }
            // Hex is only a validator representation. Scan actual blob bytes too: encoding a
            // payload into hex must never conceal it from the shared injection catalogue.
            if is_hex {
                let scan = payloads::scan(&raw, limits)?;
                if !scan.is_clean() {
                    emit(self.finding(
                        file,
                        row,
                        &format!(
                            "payload catalogue match in native bytes: {}",
                            scan.classes.join(", ")
                        ),
                        &raw,
                    ))?;
                }
            }
            return Ok(());
        }
        match &self.ty {
            Ch::Array(_) | Ch::Nested(_) => {
                let values = list_value(array, at)?;
                if values.len() > limits.max_array_elements as usize {
                    return emit(self.finding(file, row, "array exceeds pinned element cap", &[]));
                }
                if matches!(self.ty, Ch::Nested(_)) {
                    let structs = cast::<StructArray>(values.as_ref())?;
                    for i in 0..structs.len() {
                        if structs.is_null(i) {
                            emit(self.finding(file, row, "NULL Nested entry", &[]))?;
                            continue;
                        }
                        for (node, col) in self.children.iter().zip(structs.columns()) {
                            node.check(col.as_ref(), i, limits, file, row, remaining, emit)?;
                        }
                    }
                } else {
                    for i in 0..values.len() {
                        self.children[0].check(
                            values.as_ref(),
                            i,
                            limits,
                            file,
                            row,
                            remaining,
                            emit,
                        )?;
                    }
                }
            }
            Ch::Tuple(_) => {
                for (node, col) in self
                    .children
                    .iter()
                    .zip(cast::<StructArray>(array)?.columns())
                {
                    node.check(col.as_ref(), at, limits, file, row, remaining, emit)?;
                }
            }
            Ch::Map(_, _) => {
                let entries = cast::<MapArray>(array)?.value(at);
                if entries.len() > limits.max_array_elements as usize {
                    return emit(self.finding(file, row, "map exceeds pinned element cap", &[]));
                }
                for i in 0..entries.len() {
                    if entries.is_null(i) || entries.column(0).is_null(i) {
                        emit(self.finding(file, row, "NULL map entry/key", &[]))?;
                        continue;
                    }
                    for (node, col) in self.children.iter().zip(entries.columns()) {
                        node.check(col.as_ref(), i, limits, file, row, remaining, emit)?;
                    }
                }
            }
            _ => return abort("unsupported native container"),
        }
        Ok(())
    }

    fn finding(&self, file: u32, row: u64, reason: &str, bytes: &[u8]) -> Finding {
        Finding {
            phase: "bounds".into(),
            column: Some(self.name.clone()),
            page: Some(file),
            row: Some(row),
            reason: reason.into(),
            escalate: true,
            sample_hex: hex(&bytes[..bytes.len().min(64)]),
        }
    }
}

impl Contract {
    pub fn check_row(
        &self,
        batch: &RecordBatch,
        at: usize,
        limits: &Limits,
        file: u32,
        row: u64,
        emit: &mut impl FnMut(Finding) -> Result<()>,
    ) -> Result<()> {
        for (node, index) in self.nodes.iter().zip(&self.kept) {
            let mut remaining = limits.max_field_bytes;
            node.check(
                batch.column(*index).as_ref(),
                at,
                limits,
                file,
                row,
                &mut remaining,
                emit,
            )?;
        }
        Ok(())
    }
}

fn cast<T: Array + 'static>(a: &dyn Array) -> Result<&T> {
    a.as_any()
        .downcast_ref()
        .ok_or_else(|| abort::<()>("native array differs from checked schema").unwrap_err())
}

fn list_value(a: &dyn Array, at: usize) -> Result<ArrayRef> {
    match a.data_type() {
        DataType::List(_) => Ok(cast::<ListArray>(a)?.value(at)),
        DataType::LargeList(_) => Ok(cast::<LargeListArray>(a)?.value(at)),
        _ => abort("expected native list"),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn scalar_bytes(a: &dyn Array, at: usize, ty: &Ch) -> Result<Vec<u8>> {
    macro_rules! value {
        ($t:ty) => {
            cast::<$t>(a)?.value(at)
        };
    }
    let bytes = match a.data_type() {
        DataType::Utf8 => value!(StringArray).as_bytes().to_vec(),
        DataType::LargeUtf8 => value!(LargeStringArray).as_bytes().to_vec(),
        DataType::Binary => value!(BinaryArray).to_vec(),
        DataType::LargeBinary => value!(LargeBinaryArray).to_vec(),
        DataType::FixedSizeBinary(_) => value!(FixedSizeBinaryArray).to_vec(),
        DataType::UInt8 => value!(UInt8Array).to_string().into_bytes(),
        DataType::UInt16 => value!(UInt16Array).to_string().into_bytes(),
        DataType::UInt32 if matches!(ty, Ch::Ipv4) => std::net::Ipv4Addr::from(value!(UInt32Array))
            .to_string()
            .into_bytes(),
        DataType::UInt32 => value!(UInt32Array).to_string().into_bytes(),
        DataType::UInt64 => value!(UInt64Array).to_string().into_bytes(),
        DataType::Int8 => value!(Int8Array).to_string().into_bytes(),
        DataType::Int16 => value!(Int16Array).to_string().into_bytes(),
        DataType::Int32 => value!(Int32Array).to_string().into_bytes(),
        DataType::Int64 => value!(Int64Array).to_string().into_bytes(),
        DataType::Float32 => format!("{:08x}", value!(Float32Array).to_bits()).into_bytes(),
        DataType::Float64 => format!("{:016x}", value!(Float64Array).to_bits()).into_bytes(),
        DataType::Boolean => {
            if value!(BooleanArray) {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            }
        }
        DataType::Decimal128(_, s) => {
            decimal(value!(Decimal128Array).to_string(), *s)?.into_bytes()
        }
        DataType::Decimal256(_, s) => {
            decimal(value!(Decimal256Array).to_string(), *s)?.into_bytes()
        }
        DataType::Date32 => {
            let date =
                time::OffsetDateTime::from_unix_timestamp(i64::from(value!(Date32Array)) * 86400)
                    .map_err(|_| abort::<()>("date outside representable range").unwrap_err())?;
            format!(
                "{:04}-{:02}-{:02}",
                date.year(),
                u8::from(date.month()),
                date.day()
            )
            .into_bytes()
        }
        DataType::Timestamp(unit, _) => {
            let (ticks, divisor) = match unit {
                TimeUnit::Second => (value!(TimestampSecondArray), 1i64),
                TimeUnit::Millisecond => (value!(TimestampMillisecondArray), 1000),
                TimeUnit::Microsecond => (value!(TimestampMicrosecondArray), 1_000_000),
                TimeUnit::Nanosecond => (value!(TimestampNanosecondArray), 1_000_000_000),
            };
            let seconds = ticks.div_euclid(divisor);
            let nanos = ticks.rem_euclid(divisor) * (1_000_000_000 / divisor);
            if matches!(ty, Ch::DateTime) {
                if nanos != 0 {
                    return abort("fractional timestamp in DateTime");
                }
                seconds.to_string().into_bytes()
            } else {
                let Ch::DateTime64 { scale } = ty else {
                    return abort("unexpected timestamp type");
                };
                let quantum = 10i64.pow(u32::from(9 - *scale));
                if nanos % quantum != 0 {
                    return abort("timestamp loses precision at pinned scale");
                }
                let date = time::OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| {
                    abort::<()>("timestamp outside representable range").unwrap_err()
                })?;
                let mut text = format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                    date.year(),
                    u8::from(date.month()),
                    date.day(),
                    date.hour(),
                    date.minute(),
                    date.second()
                );
                if *scale > 0 {
                    text.push_str(&format!(
                        ".{:0width$}",
                        nanos / quantum,
                        width = usize::from(*scale)
                    ));
                }
                text.into_bytes()
            }
        }
        _ => return abort("unsupported native scalar"),
    };
    match ty {
        Ch::Uuid
            if matches!(
                a.data_type(),
                DataType::Binary | DataType::FixedSizeBinary(_)
            ) =>
        {
            Ok(uuid::Uuid::from_slice(&bytes)
                .map_err(|_| abort::<()>("UUID must contain 16 bytes").unwrap_err())?
                .to_string()
                .into_bytes())
        }
        Ch::Ipv6
            if matches!(
                a.data_type(),
                DataType::Binary | DataType::FixedSizeBinary(_)
            ) =>
        {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| abort::<()>("IPv6 must contain 16 bytes").unwrap_err())?;
            Ok(std::net::Ipv6Addr::from(octets).to_string().into_bytes())
        }
        Ch::Enum8(ids) | Ch::Enum16(ids)
            if matches!(a.data_type(), DataType::Utf8 | DataType::LargeUtf8) =>
        {
            let (_, id) = ids
                .iter()
                .find(|(label, _)| label.as_bytes() == bytes)
                .ok_or_else(|| abort::<()>("enum label absent from pinned DDL").unwrap_err())?;
            Ok(id.to_string().into_bytes())
        }
        _ => Ok(bytes),
    }
}

fn decimal(raw: String, scale: i8) -> Result<String> {
    let scale =
        usize::try_from(scale).map_err(|_| abort::<()>("negative decimal scale").unwrap_err())?;
    if scale == 0 {
        return Ok(raw);
    }
    let negative = raw.starts_with('-');
    let digits = raw.trim_start_matches('-');
    let padded = format!("{:0>width$}", digits, width = (scale + 1).max(digits.len()));
    let split = padded.len() - scale;
    Ok(format!(
        "{}{}.{}",
        if negative { "-" } else { "" },
        &padded[..split],
        &padded[split..]
    ))
}

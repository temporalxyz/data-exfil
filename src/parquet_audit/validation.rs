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
    iocs: Option<Arc<regex::bytes::RegexSet>>,
    binary: bool,
    encoded: Option<EncodedField>,
    recognize_solana: bool,
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

/// Build contracts directly from native Parquet fields. No SQL text is loaded or generated.
pub fn build_native(
    policy: &super::policy::TablePolicy,
    overrides: &Overrides,
    schema: &Schema,
) -> Result<Contract> {
    if schema.fields().is_empty()
        || schema.fields().len() > overrides.limits.max_fields_per_row as usize
    {
        return abort("native schema has no fields or exceeds field cap");
    }
    let iocs = if policy.iocs.is_empty() {
        None
    } else {
        Some(Arc::new(
            regex::bytes::RegexSetBuilder::new(policy.iocs.iter().map(|s| regex::escape(s)))
                .size_limit(4 * 1024 * 1024)
                .build()
                .map_err(|_| usage::<()>("incident indicators exceed regex budget").unwrap_err())?,
        ))
    };
    let mut names = std::collections::BTreeSet::new();
    let mut kept = Vec::new();
    let mut nodes = Vec::new();
    let mut fields = Vec::new();
    for (index, field) in schema.fields().iter().enumerate() {
        let name = field.name();
        if !names.insert(name.clone())
            || crate::clickhouse::quarantine::PROVENANCE_COLUMNS
                .iter()
                .any(|(n, _)| n == name)
        {
            return abort("duplicate field or source/audit provenance collision");
        }
        crate::clickhouse::types::Ident::new(name)?;
        let inferred = native_type(field, &overrides.limits, 1)?;
        // Operator-selected contracts, scoped to these exact top-level column names.
        let default_type = match name.as_str() {
            "signature" => Some("SolanaSignature"),
            "token_a" | "token_b" | "fee_payer" => Some("SolanaPublicKey"),
            _ => None,
        };
        let explicit = policy.types.get(name).map(String::as_str);
        if default_type
            .zip(explicit)
            .is_some_and(|(required, actual)| required != actual)
        {
            return usage("column semantic override conflicts with its required Solana contract");
        }
        let encoded = match default_type.or(explicit) {
            Some("SolanaSignature") => Some(EncodedField::Signature),
            Some("SolanaPublicKey") => Some(EncodedField::PublicKey),
            _ => None,
        };
        if encoded.is_some() && !matches!(field.data_type(), DataType::Utf8 | DataType::LargeUtf8) {
            return usage("encoded Solana fields require native string columns");
        }
        let ty = if let Some(semantic) = policy.types.get(name).filter(|_| encoded.is_none()) {
            let ty = crate::clickhouse::types::parse_type(semantic)?;
            if field.is_nullable() {
                Ch::Nullable(Box::new(ty))
            } else {
                ty
            }
        } else {
            inferred
        };
        let over = overrides.columns.get(name);
        let mut node = Node::build(
            name.clone(),
            &ty,
            field.data_type(),
            over,
            &overrides.limits,
        )?;
        if encoded.is_some() && over.is_some_and(|o| o.hex || o.enum_ids.is_some()) {
            return usage("encoded Solana fields cannot use hex or enum overrides");
        }
        node.encoded = encoded;
        configure_native(&mut node, over, &iocs)?;
        if encoded.is_some() {
            node.scalar.as_mut().unwrap().class = FreedomClass::Closed;
        }
        if over.is_some_and(|o| o.drop) {
            continue;
        }
        kept.push(index);
        nodes.push(node);
        fields.push(clean_field(field));
    }
    if policy
        .columns
        .keys()
        .chain(policy.types.keys())
        .any(|name| !names.contains(name))
    {
        return usage("field policy names a column absent from Parquet schema");
    }
    if kept.is_empty() {
        return usage("every native column is dropped");
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

fn configure_native(
    node: &mut Node,
    over: Option<&ColumnOverride>,
    iocs: &Option<Arc<regex::bytes::RegexSet>>,
) -> Result<()> {
    node.iocs = iocs.clone();
    node.recognize_solana = !node.binary && node.scalar.is_some();
    if let Some(scalar) = &mut node.scalar {
        if node.binary && matches!(node.ty, Ch::String) {
            scalar.validator = Validator::HexAny;
        }
        if matches!(node.ty, Ch::String | Ch::FixedString(_)) {
            if over.is_none() {
                scalar.class = FreedomClass::Open;
            }
            if matches!(
                scalar.class,
                FreedomClass::Closed | FreedomClass::Constrained
            ) && node.encoded.is_none()
                && scalar.pattern.is_none()
                && !over.is_some_and(|o| o.drop || o.hex)
            {
                return usage(
                    "closed/constrained native strings require an explicit anchored pattern",
                );
            }
        }
        if let Some(ids) = over.and_then(|o| o.enum_ids.as_ref()) {
            if !matches!(
                node.ty,
                Ch::Int(_) | Ch::UInt(_) | Ch::Enum8(_) | Ch::Enum16(_)
            ) {
                return usage("enum_ids requires a native integer or explicit enum type");
            }
            scalar.validator = Validator::EnumId { ids: ids.clone() };
        }
    }
    for child in &mut node.children {
        configure_native(child, over, iocs)?;
    }
    Ok(())
}

fn native_type(field: &ArrowField, limits: &Limits, depth: u32) -> Result<Ch> {
    use crate::clickhouse::types::IntWidth as W;
    if depth > limits.max_nesting_depth {
        return abort("native type exceeds nesting cap");
    }
    let child = |f: &ArrowField| native_type(f, limits, depth + 1);
    let ty = match field.data_type() {
        DataType::Int8 => Ch::Int(W::W8),
        DataType::Int16 => Ch::Int(W::W16),
        DataType::Int32 => Ch::Int(W::W32),
        DataType::Int64 => Ch::Int(W::W64),
        DataType::UInt8 => Ch::UInt(W::W8),
        DataType::UInt16 => Ch::UInt(W::W16),
        DataType::UInt32 => Ch::UInt(W::W32),
        DataType::UInt64 => Ch::UInt(W::W64),
        DataType::Boolean => Ch::Bool,
        DataType::Float32 => Ch::Float(FloatWidth::F32),
        DataType::Float64 => Ch::Float(FloatWidth::F64),
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Binary | DataType::LargeBinary => {
            Ch::String
        }
        DataType::FixedSizeBinary(n) if *n > 0 => Ch::FixedString(*n as u32),
        DataType::Decimal128(p, s) | DataType::Decimal256(p, s) if *s >= 0 && *s as u8 <= *p => {
            Ch::Decimal {
                p: u32::from(*p),
                s: *s as u32,
            }
        }
        DataType::Date32 => Ch::Date32,
        DataType::Timestamp(unit, _) => Ch::DateTime64 {
            scale: match unit {
                TimeUnit::Second => 0,
                TimeUnit::Millisecond => 3,
                TimeUnit::Microsecond => 6,
                TimeUnit::Nanosecond => 9,
            },
        },
        DataType::List(f) | DataType::LargeList(f) => Ch::Array(Box::new(child(f)?)),
        DataType::Struct(fs) => {
            if fs.is_empty() || fs.len() > limits.max_fields_per_row as usize {
                return abort("native struct field count exceeds bounds");
            }
            let mut names = std::collections::BTreeSet::new();
            for f in fs {
                crate::clickhouse::types::Ident::new(f.name())?;
                if !names.insert(f.name()) {
                    return abort("duplicate native struct field");
                }
            }
            Ch::Tuple(fs.iter().map(|f| child(f)).collect::<Result<Vec<_>>>()?)
        }
        DataType::Map(entries, _) => {
            let DataType::Struct(fs) = entries.data_type() else {
                return abort("invalid native map structure");
            };
            if fs.len() != 2 || entries.is_nullable() || fs[0].is_nullable() {
                return abort("native map requires non-null entries and keys");
            }
            Ch::Map(Box::new(child(&fs[0])?), Box::new(child(&fs[1])?))
        }
        _ => return abort("unsupported Parquet logical type; no implicit conversion permitted"),
    };
    Ok(if field.is_nullable() {
        Ch::Nullable(Box::new(ty))
    } else {
        ty
    })
}

pub fn clean_schema(schema: &Schema) -> Schema {
    Schema::new(
        schema
            .fields()
            .iter()
            .map(|f| clean_field(f))
            .collect::<Vec<_>>(),
    )
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
            iocs: None,
            encoded: None,
            recognize_solana: false,
            binary: matches!(
                dt,
                DataType::Binary | DataType::LargeBinary | DataType::FixedSizeBinary(_)
            ),
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
            if let Some(encoded) = self.encoded {
                let decoded = match encoded {
                    EncodedField::Signature => decode_solana_signature(&raw).map(|b| b.to_vec()),
                    EncodedField::PublicKey => decode_solana_public_key(&raw).map(|b| b.to_vec()),
                };
                let Some(decoded) = decoded else {
                    return emit(self.finding(file, row, encoded.failure(), &raw));
                };
                if contract.max_len.is_some_and(|cap| raw.len() > cap as usize)
                    || self.pattern.is_some_and(|p| !p.is_match(&raw))
                {
                    return emit(self.finding(
                        file,
                        row,
                        "encoded Solana value violates its explicit field constraints",
                        &raw,
                    ));
                }
                // Signature and public-key bytes are opaque, not text to run through speculative decoders.
                // Keep explicitly supplied incident indicators on both exact representations.
                if self
                    .iocs
                    .as_ref()
                    .is_some_and(|i| i.is_match(&raw) || i.is_match(&decoded))
                {
                    return emit(self.finding(
                        file,
                        row,
                        "payload catalogue match: ioc_canary in encoded Solana value",
                        &raw,
                    ));
                }
                return Ok(());
            }
            let is_hex = matches!(
                contract.validator,
                Validator::HexAny | Validator::HexExact { .. }
            ) && matches!(self.ty, Ch::String | Ch::FixedString(_));
            let value = if is_hex {
                hex(&raw).into_bytes()
            } else {
                raw.clone()
            };
            // Only source text/blob fields can contain encoded text payloads. Numeric,
            // boolean and temporal representations below were generated by scalar_bytes.
            let source_text = matches!(
                array.data_type(),
                DataType::Utf8
                    | DataType::LargeUtf8
                    | DataType::Binary
                    | DataType::LargeBinary
                    | DataType::FixedSizeBinary(_)
            );
            // Operator-approved representation heuristic for string leaves, including nested
            // fields. Still run the complete declared validator and explicit constraints.
            let opaque_solana = if self.recognize_solana
                && matches!(array.data_type(), DataType::Utf8 | DataType::LargeUtf8)
            {
                decode_solana_public_key(&raw)
                    .map(|b| b.to_vec())
                    .or_else(|| decode_solana_signature(&raw).map(|b| b.to_vec()))
            } else {
                None
            };
            let check = if source_text && opaque_solana.is_none() {
                bounds::check_value_precompiled
            } else {
                bounds::check_constraints_precompiled
            };
            if let Some(finding) = check(
                contract,
                &Field::Value(value),
                limits,
                file,
                row,
                self.pattern,
            )? {
                emit(finding)?;
            }
            if let Some(iocs) = &self.iocs {
                let matched = if let Some(decoded) = &opaque_solana {
                    iocs.is_match(&raw) || iocs.is_match(decoded)
                } else if source_text {
                    payloads::scan_with_iocs(&raw, limits, Some(iocs))?
                        .classes
                        .contains(&"ioc_canary")
                } else {
                    iocs.is_match(&raw)
                };
                if matched {
                    emit(self.finding(file, row, "payload catalogue match: ioc_canary", &raw))?;
                }
            }
            // Hex is only a validator representation. Scan actual blob bytes too: encoding a
            // payload into hex must never conceal it from the shared injection catalogue.
            if is_hex && opaque_solana.is_none() {
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FieldAudit {
    pub column: String,
    pub validated_type: String,
    pub class: FreedomClass,
    pub pattern: Option<String>,
    pub max_len: Option<u32>,
    pub opaque_binary: bool,
    #[serde(default)]
    pub recognizes_solana_encodings: bool,
    pub enum_ids: Option<Vec<i16>>,
}

impl Contract {
    pub fn field_audits(&self) -> Vec<FieldAudit> {
        fn visit(node: &Node, result: &mut Vec<FieldAudit>) {
            if let Some(scalar) = &node.scalar {
                result.push(FieldAudit {
                    column: node.name.clone(),
                    validated_type: node
                        .encoded
                        .map_or_else(|| node.ty.canonical(), |kind| kind.label().into()),
                    class: scalar.class,
                    pattern: scalar.pattern.clone(),
                    max_len: scalar.max_len,
                    opaque_binary: node.binary,
                    recognizes_solana_encodings: node.recognize_solana
                        && matches!(node.ty, Ch::String | Ch::FixedString(_)),
                    enum_ids: match &scalar.validator {
                        Validator::EnumId { ids } => Some(ids.clone()),
                        _ => None,
                    },
                });
            }
            for child in &node.children {
                visit(child, result);
            }
        }
        let mut result = Vec::new();
        for node in &self.nodes {
            visit(node, &mut result);
        }
        result
    }
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

/// A structural signature contract, not cryptographic transaction verification.
fn decode_solana_signature(raw: &[u8]) -> Option<[u8; 64]> {
    use base64::Engine as _;
    if !(64..=88).contains(&raw.len()) {
        return None;
    }
    let mut bytes = [0u8; 64];
    if bs58::decode(raw).onto(&mut bytes).ok() == Some(64)
        && bs58::encode(bytes).into_string().as_bytes() == raw
    {
        return Some(bytes);
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(decoded) = engine.decode(raw)
            && decoded.len() == 64
            && engine.encode(&decoded).as_bytes() == raw
        {
            return decoded.try_into().ok();
        }
    }
    None
}

#[derive(Clone, Copy)]
enum EncodedField {
    Signature,
    PublicKey,
}
impl EncodedField {
    fn label(self) -> &'static str {
        match self {
            Self::Signature => "SolanaSignature(base58|base64,64 bytes)",
            Self::PublicKey => "SolanaPublicKey(base58,32 bytes)",
        }
    }
    fn failure(self) -> &'static str {
        match self {
            Self::Signature => {
                "Solana signature must be canonical base58 or base64 encoding of exactly 64 bytes"
            }
            Self::PublicKey => {
                "Solana public key must be canonical base58 encoding of exactly 32 bytes"
            }
        }
    }
}

fn decode_solana_public_key(raw: &[u8]) -> Option<[u8; 32]> {
    if !(32..=44).contains(&raw.len()) {
        return None;
    }
    let mut bytes = [0u8; 32];
    if bs58::decode(raw).onto(&mut bytes).ok() == Some(32)
        && bs58::encode(bytes).into_string().as_bytes() == raw
    {
        Some(bytes)
    } else {
        None
    }
}

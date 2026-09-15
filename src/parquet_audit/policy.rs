//! Optional semantic rules. Native Parquet, not SQL DDL, supplies the type contract.
use super::*;
use crate::limits::Limits;
use crate::models::ColumnOverride;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TablePolicy {
    pub columns: BTreeMap<String, ColumnOverride>,
    /// Optional semantic refinement (e.g. UUID, IPv4, Enum8). Never inferred from names.
    pub types: BTreeMap<String, String>,
    /// Literal incident indicators, scanned raw, normalized and after bounded decoding.
    pub iocs: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Policy {
    limits: BTreeMap<String, u64>,
    iocs: Vec<String>,
    tables: BTreeMap<String, TablePolicy>,
}

pub fn default_limits() -> Limits {
    Limits {
        max_compressed_bytes: 32 * 1024 * MIB,
        max_uncompressed_bytes: 256 * 1024 * MIB,
        max_expansion_ratio: 100,
        max_rows_per_page: 1_000_000_000,
        max_fields_per_row: 4096,
        max_field_bytes: MIB,
        max_array_elements: 4096,
        max_nesting_depth: 8,
        max_tar_members: 16,
        max_tar_member_bytes: 256 * 1024 * MIB,
        max_tar_name_bytes: 128,
        max_decode_rounds: 2,
        max_decode_expansion_ratio: 8,
        wall_clock_secs: 3600,
    }
}

pub fn load_table(
    args: &ParquetArgs,
    table: &str,
) -> Result<(Overrides, TablePolicy, Option<super::target::ProdSchema>)> {
    let policy = if let Some(path) = &args.audit_policy {
        if std::fs::metadata(path).map_err(infrastructure)?.len() > 4 * MIB {
            return usage("audit policy exceeds 4 MiB");
        }
        toml::from_str::<Policy>(&std::fs::read_to_string(path).map_err(infrastructure)?)
            .map_err(|_| usage::<()>("invalid Parquet audit policy").unwrap_err())?
    } else {
        Policy::default()
    };
    let mut limits = serde_json::to_value(default_limits()).map_err(infrastructure)?;
    for (key, value) in policy.limits {
        if value == 0 || limits.get(&key).is_none() {
            return usage("unknown or zero audit limit");
        }
        limits[&key] = value.into();
    }
    let limits: Limits = serde_json::from_value(limits).map_err(infrastructure)?;
    if limits.max_nesting_depth > 64
        || limits.max_decode_rounds > 8
        || limits.max_decode_expansion_ratio > 64
    {
        return usage("audit recursion/decoding limits exceed supported ceilings");
    }
    let mut native = policy.tables.get(table).cloned().unwrap_or_default();
    native.iocs.extend(policy.iocs);
    if native.iocs.len() > 1024
        || native.iocs.iter().any(|i| i.is_empty())
        || native.iocs.iter().map(String::len).sum::<usize>() > 65536
    {
        return usage("incident indicators must be nonempty and bounded to 1024 entries / 64 KiB");
    }
    let overrides = Overrides {
        cutoff_column: String::new(),
        cutoff_value: String::new(),
        cursor_columns: None,
        page_byte_budget: args.row_group_bytes,
        limits,
        columns: native.columns.clone(),
    };
    overrides.validate()?;
    let prod = args
        .prod_schema_dir
        .as_deref()
        .map(|dir| super::target::load(dir, table))
        .transpose()?;
    Ok((overrides, native, prod))
}

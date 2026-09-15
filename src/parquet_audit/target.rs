//! Pinned target schemas, so a table migrated in production can still be audited as one table.
//!
//! A migration leaves older partitions a column short of newer ones, and the audit's per-table
//! schema pin rejects that as drift. This module lets the operator declare what the table is
//! *now*, so every partition is published against that one shape and the columns a partition
//! predates are written as nulls.
//!
//! # Why the CREATE TABLE is not the whole answer
//!
//! A ClickHouse type does not determine a Parquet column's Arrow type, and this is not a gap that
//! more parsing would close:
//!
//! - `String` is `Utf8`, `LargeUtf8`, `Binary` or `LargeBinary` -- `validation::native_type` maps
//!   all four back to `Ch::String`, and no CREATE TABLE syntax distinguishes them.
//! - `parse_type` reads a `DateTime64` scale and discards the timezone, so `DateTime64(3)` and
//!   `DateTime64(3, 'UTC')` are one type here while `Timestamp(Millisecond, None)` and
//!   `Timestamp(Millisecond, Some("UTC"))` are two, and arrow will not write one as the other.
//! - `UUID`, `IPv6`, `IPv4`, `Enum8`/`Enum16` and `Decimal128`/`Decimal256` are each ambiguous the
//!   same way, `Tuple` field names are dropped by the parser, and `UInt128`/`Int128`/`UInt256`/
//!   `Int256` have no Arrow type at all.
//!
//! Picking a representative for each would mean guessing, and guessing wrong rejects exactly the
//! old partitions this exists to rescue. So the DDL is the authority for **which columns exist, in
//! what order, and which are nullable**, and the Arrow types are read from a real post-migration
//! object. The two are cross-checked against each other before either is trusted.
use std::path::Path;

use arrow_schema::{Field as ArrowField, Schema};

use super::{Result, abort, infrastructure, usage};
use crate::clickhouse::ddl::{PinnedDdl, parse_prod_create_table};
use crate::clickhouse::types::ClickHouseType as Ch;
use crate::models::Overrides;

/// A prod `CREATE TABLE` grows no larger than this. Read before parsing, like the audit policy.
const MAX_DDL_BYTES: u64 = 4 * super::MIB;

/// The pinned SQL for one table, kept as text so it can be hashed into the run's contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProdSchema {
    pub sql: String,
    pub ddl: PinnedDdl,
}

/// Read this table's `CREATE TABLE`: `<dir>/<db>.<table>.sql`, mirroring `ddl/`, or the
/// `<dir>/create_<table>.sql` layout a schema repository keeps.
///
/// Absence is an error rather than a fallback: a run told to project must project every table, or
/// the destination ends up holding two different shapes for the same database.
pub fn load(dir: &Path, table: &str) -> Result<ProdSchema> {
    let unqualified = table.rsplit('.').next().unwrap_or(table);
    let candidates = [
        dir.join(format!("{table}.sql")),
        dir.join(format!("create_{unqualified}.sql")),
    ];
    let Some(path) = candidates.iter().find(|p| p.is_file()) else {
        return usage("no prod schema for this table in --prod-schema-dir").map_err(
            |e: crate::abort::SalvageError| {
                e.with("tried", candidates[0].display())
                    .with("or", candidates[1].display())
            },
        );
    };
    if std::fs::metadata(path).map_err(infrastructure)?.len() > MAX_DDL_BYTES {
        return usage("prod schema exceeds 4 MiB");
    }
    let sql = std::fs::read_to_string(path).map_err(infrastructure)?;
    let ddl = parse_prod_create_table(&sql)?;
    if ddl.qualified() != table {
        return usage("prod schema declares a different table than its filename").map_err(
            |e: crate::abort::SalvageError| e.with("file", table).with("declares", ddl.qualified()),
        );
    }
    Ok(ProdSchema { sql, ddl })
}

/// The two real objects a target is derived from.
pub struct References<'a> {
    /// The newest selected partition's shape: where the Arrow types come from.
    pub newest: &'a Schema,
    /// The oldest selected partition's shape: which columns the range started without.
    pub oldest: &'a Schema,
}

/// Build the target Arrow schema: the DDL's columns and order, the newest object's types, and
/// nullability from the DDL **except** that a column the oldest partition lacks is nullable.
///
/// That exception is the point of the feature. A migration adds `uid UInt64` and every partition
/// before it has no `uid`; publishing them means writing something there, and the only honest
/// thing to write is null. So the published type widens to `Nullable(UInt64)` for the whole
/// table -- every partition, so they still share one shape -- and the manifest of each padded
/// partition names the column. Nothing is invented: not the server's implicit default, not the
/// DDL's `DEFAULT` expression.
///
/// Cross-checking runs both ways, so neither a DDL that has run ahead of the data nor a newest
/// object that is itself pre-migration can quietly become the contract. A column the oldest
/// object has and the DDL does not is a column a migration dropped; the operator names it with
/// `drop = true` and it is excluded from every partition.
pub fn build(prod: &ProdSchema, refs: References<'_>, overrides: &Overrides) -> Result<Schema> {
    let columns = &prod.ddl.columns;
    if columns.is_empty() || columns.len() > overrides.limits.max_fields_per_row as usize {
        return abort("prod schema has no columns or exceeds the field cap");
    }
    let mut fields = Vec::new();
    for column in columns {
        let name = column.name.as_str();
        let declared_nullable = matches!(column.ty, Ch::Nullable(_));
        // Prefer a real object's type, newest first; the newest is the shape the table has now.
        let observed = refs
            .newest
            .field_with_name(name)
            .or_else(|_| refs.oldest.field_with_name(name))
            .ok();
        let arrow_type = match observed {
            Some(field) => {
                // Checking the pair through the same matrix the per-file audit uses means a
                // target can never be built that the audit would then refuse column by column.
                validation_accepts(&column.ty, field, &overrides.limits, name)?;
                // Caught here rather than left to the per-file projection, which would refuse the
                // very object this target was derived from and report it as though the data were
                // at fault.
                if field.is_nullable() && !declared_nullable {
                    return abort(
                        "prod schema declares this column NOT NULL but a reference object writes \
                         it nullable",
                    )
                    .map_err(|e: crate::abort::SalvageError| e.with("column", name));
                }
                super::validation::clean_field_type(field)
            }
            // No object in the range carries it: the migration that added it ran after the range
            // ended. It can only be published as nulls, but it still needs a type, and one is
            // taken only where the declared type has exactly one Arrow spelling.
            None => super::validation::unambiguous_arrow_type(&column.ty).ok_or_else(|| {
                abort::<()>(
                    "no object in this range carries this column and its declared type has more \
                     than one Parquet spelling, so its type cannot be known; extend the range to \
                     a partition that carries it, or set drop = true for it in --audit-policy",
                )
                .unwrap_err()
                .with("column", name)
                .with("declared", &column.declared_type)
            })?,
        };
        // Nullable if either reference lacks it: whichever partitions lack it are padded, and a
        // NOT NULL column cannot hold a pad. Columns every reference carries keep the DDL's word.
        let padded_somewhere = refs.oldest.field_with_name(name).is_err()
            || refs.newest.field_with_name(name).is_err();
        fields.push(ArrowField::new(
            name,
            arrow_type,
            declared_nullable || padded_somewhere,
        ));
    }
    // A column either object has and the DDL does not is a column a migration dropped. Named
    // with `drop = true` it is excluded from every partition; unnamed, it would vanish from the
    // output unannounced, and section 8.7 makes every removal explicit.
    for field in refs.newest.fields().iter().chain(refs.oldest.fields()) {
        if prod.ddl.column(field.name()).is_none()
            && !overrides.columns.get(field.name()).is_some_and(|c| c.drop)
        {
            return abort(
                "a reference object has a column the prod schema does not declare; if a migration \
                 dropped it, set drop = true for it in --audit-policy",
            )
            .map_err(|e: crate::abort::SalvageError| e.with("column", field.name()));
        }
    }
    Ok(Schema::new(fields))
}

/// Reuse the audit's own ClickHouse/Arrow compatibility matrix rather than restating it.
fn validation_accepts(
    ty: &Ch,
    field: &ArrowField,
    limits: &crate::limits::Limits,
    name: &str,
) -> Result<()> {
    super::validation::accepts(ty, field.data_type(), limits).map_err(|e| {
        e.with("column", name)
            .with("declared", format!("{ty:?}"))
            .with("parquet", format!("{:?}", field.data_type()))
    })
}

/// Read the Arrow schema of one already-listed source object.
///
/// Costs one extra object download per table for the whole run, against a run that downloads every
/// object in its range anyway. The reader options match the per-file audit's exactly, because the
/// schema this returns is compared for equality against the ones that audit produces.
pub async fn reference_schema(
    store: &dyn super::Store,
    source: &super::Source,
    work: &Path,
    accept_ch74988: bool,
) -> Result<Schema> {
    use std::io::{Read, Seek, SeekFrom};
    tracing::info!(
        key = source.key,
        bytes = source.size,
        "reading reference object schema"
    );
    std::fs::create_dir_all(work).map_err(infrastructure)?;
    let path = work.join("REFERENCE.parquet");
    let downloaded = store.download(source, &path).await;
    let schema = downloaded.and_then(|_| {
        // Named, keyed and sized: the operator has to be able to tell a half-written object
        // in today's partition from a corrupt one without re-downloading it by hand.
        let context =
            |e: crate::abort::SalvageError| e.with("key", &source.key).with("bytes", source.size);
        let mut file = std::fs::File::open(&path).map_err(infrastructure)?;
        let size = file.metadata().map_err(infrastructure)?.len();
        if size < 12 {
            return Err(context(
                abort::<()>("reference object is too short to be Parquet").unwrap_err(),
            ));
        }
        file.seek(SeekFrom::End(-8)).map_err(infrastructure)?;
        let mut trailer = [0u8; 8];
        file.read_exact(&mut trailer).map_err(infrastructure)?;
        let footer_len = u64::from(u32::from_le_bytes([
            trailer[0], trailer[1], trailer[2], trailer[3],
        ]));
        if &trailer[4..] != b"PAR1" || footer_len > size - 12 || footer_len > 8 * super::MIB {
            return Err(context(
                abort::<()>("reference object has an invalid or oversized Parquet footer")
                    .unwrap_err(),
            ));
        }
        let (builder, _corrections) = super::footer::open(
            file,
            &super::footer::Footer {
                start: size - 8 - footer_len,
                len: footer_len,
            },
            accept_ch74988,
        )
        .map_err(context)?;
        Ok(super::validation::clean_schema(builder.schema()))
    });
    // Reclaim the scratch whether or not the read worked; nothing downstream reads this copy.
    let _ = std::fs::remove_file(&path);
    schema
}

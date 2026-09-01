//! The rotation inventory (addition A3), and the column classes it is built from.
//!
//! The source plan has an IoC/canary class in section 8.6 but nothing for *"this value is a live
//! credential"*, and no rotation step at all. That is the gap this module fills, and the scoping
//! rule is the important half:
//!
//! **Rotation scope is not "secrets we found".** The attacker had root on the cluster, so it is
//! every secret the compromised cluster *could* hold -- including secrets in columns we drop and
//! tables we exclude from scope. A column dropped under section 8.7 is a column we chose not to
//! carry, not a column the attacker could not read.
//!
//! It follows that this is driven by the pinned DDL and column names, and never by what detection
//! happens to match. Detection runs later, over data; this runs at incident time, before any data
//! moves, and its output does not depend on the salvage succeeding. Section A3: *"Rotation
//! proceeds regardless of whether the batch ever ships."*

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::abort::Result;
use crate::clickhouse::ddl::PinnedDdl;
use crate::clickhouse::types::ClickHouseType;
use crate::models::Overrides;

/// What kind of secret a column can hold. The class decides who rotates and how urgently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretClass {
    /// A password, passphrase or shared secret in usable form.
    Credential,
    /// An API key, access token or bearer token.
    Token,
    /// A session identifier -- rotation here means invalidating live sessions.
    SessionId,
    /// A password hash. Not directly usable, but offline-crackable, so it forces a reset.
    PasswordHash,
    /// Private key material or a certificate.
    PrivateKey,
    /// A connection string, which typically embeds a credential.
    ConnectionString,
}

impl SecretClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Token => "token / api key",
            Self::SessionId => "session id",
            Self::PasswordHash => "password hash",
            Self::PrivateKey => "private key / cert",
            Self::ConnectionString => "connection string",
        }
    }

    /// What rotating this class actually means, so the owner is not left to infer it.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Credential => "change the secret at the issuer; assume the old value is known",
            Self::Token => "revoke and reissue; revocation is the control, reissue is convenience",
            Self::SessionId => "invalidate every live session; reissue on next authentication",
            Self::PasswordHash => "force a reset for every affected principal",
            Self::PrivateKey => "reissue the key or certificate and revoke the old one",
            Self::ConnectionString => {
                "rotate the embedded credential, then the endpoint if it leaks topology"
            }
        }
    }
}

/// Column-name fragments that classify a column, longest and most specific first.
///
/// Matched case-insensitively as substrings, because real schemas write `user_api_key_hash` and
/// `sessionToken` in the same table. Substring matching over-matches by design -- a false positive
/// costs one rotation nobody needed, a false negative leaves a live credential in the attacker's
/// hands.
const NAME_CLASSES: &[(&str, SecretClass)] = &[
    ("private_key", SecretClass::PrivateKey),
    ("privkey", SecretClass::PrivateKey),
    ("secret_key", SecretClass::PrivateKey),
    ("certificate", SecretClass::PrivateKey),
    ("cert", SecretClass::PrivateKey),
    ("pem", SecretClass::PrivateKey),
    ("password_hash", SecretClass::PasswordHash),
    ("passwd_hash", SecretClass::PasswordHash),
    ("pwhash", SecretClass::PasswordHash),
    ("connection_string", SecretClass::ConnectionString),
    ("conn_str", SecretClass::ConnectionString),
    ("dsn", SecretClass::ConnectionString),
    ("session", SecretClass::SessionId),
    ("cookie", SecretClass::SessionId),
    ("api_key", SecretClass::Token),
    ("apikey", SecretClass::Token),
    ("access_key", SecretClass::Token),
    ("access_token", SecretClass::Token),
    ("refresh_token", SecretClass::Token),
    ("token", SecretClass::Token),
    ("bearer", SecretClass::Token),
    ("oauth", SecretClass::Token),
    ("password", SecretClass::Credential),
    ("passwd", SecretClass::Credential),
    ("passphrase", SecretClass::Credential),
    ("credential", SecretClass::Credential),
    ("secret", SecretClass::Credential),
    ("auth", SecretClass::Token),
];

/// Classify a column by name. `None` means no name match, **not** "cannot hold a secret".
#[must_use]
pub fn classify_name(column: &str) -> Option<SecretClass> {
    let lower = column.to_ascii_lowercase();
    NAME_CLASSES
        .iter()
        .find(|(fragment, _)| lower.contains(fragment))
        .map(|(_, class)| *class)
}

/// Whether a column's type can hold arbitrary text, and so could hold a pasted secret regardless
/// of what it is named.
///
/// This is why the inventory has two halves. A column called `notes` is not a credential column,
/// but a support agent pasting a customer's password into it is the most ordinary thing in the
/// world, and the attacker read that column too.
#[must_use]
pub fn holds_free_text(ty: &ClickHouseType) -> bool {
    match ty {
        ClickHouseType::String | ClickHouseType::FixedString(_) => true,
        ClickHouseType::Nullable(inner) | ClickHouseType::LowCardinality(inner) => {
            holds_free_text(inner)
        }
        ClickHouseType::Array(inner) => holds_free_text(inner),
        ClickHouseType::Map(k, v) => holds_free_text(k) || holds_free_text(v),
        ClickHouseType::Tuple(parts) => parts.iter().any(holds_free_text),
        ClickHouseType::Nested(fields) => fields.iter().any(|(_, t)| holds_free_text(t)),
        _ => false,
    }
}

/// One row of the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEntry {
    pub table: String,
    pub column: String,
    pub declared_type: String,
    pub class: SecretClass,
    /// Whether the column is dropped from the salvage. **Dropped columns are still rotated** --
    /// dropping is about what we carry forward, not about what the attacker could read.
    pub dropped: bool,
    pub owner: Option<String>,
}

/// The whole inventory: classified columns, plus the free-text columns that need a human look,
/// plus the non-column secrets the salvage itself creates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationInventory {
    pub classified: Vec<SecretEntry>,
    /// Free-text columns with no name match. Not automatically in scope, but the reviewer decides
    /// that, not this code.
    pub review: Vec<SecretEntry>,
    pub tables: Vec<String>,
}

impl RotationInventory {
    /// Entries with no named owner. Section A3 wants an owner per column, so this is the gap list.
    #[must_use]
    pub fn unassigned(&self) -> Vec<&SecretEntry> {
        self.classified
            .iter()
            .filter(|e| e.owner.is_none())
            .collect()
    }
}

/// Secrets the salvage operation itself creates or assumes compromised, independent of any schema.
///
/// Section A3 names the first explicitly: Q1's read-only user is *"assumed compromised from the
/// moment it was created on that host -- created for this operation, dropped after, and in the
/// inventory."* It was typed into a machine adjacent to a cluster the attacker roots.
const OPERATIONAL_SECRETS: &[(&str, &str)] = &[
    (
        "source cluster read-only user",
        "created for this operation on a host adjacent to the compromised cluster; assumed \
         compromised from creation. Drop it at teardown and rotate anything it shared.",
    ),
    (
        "source cluster service accounts and application users",
        "every account the compromised cluster authenticated, whether or not it appears in a \
         salvaged table.",
    ),
    (
        "anything in the compromised environment's CI",
        "section 3: do not reuse CI secrets, runners, configurations, images or credentials that \
         existed there. If CI ran there, its outputs are suspect.",
    ),
];

/// Build the inventory from pinned DDL and, where present, pinned overrides.
///
/// Overrides are optional on purpose: this runs at incident time, potentially before anyone has
/// written a per-table override file. Their only contribution is the drop flag and the owner name.
pub fn inventory(tables: &[(PinnedDdl, Option<Overrides>)]) -> RotationInventory {
    let mut classified = Vec::new();
    let mut review = Vec::new();
    let mut names = Vec::new();

    for (ddl, overrides) in tables {
        let table = ddl.qualified();
        names.push(table.clone());

        for column in &ddl.columns {
            let over = overrides
                .as_ref()
                .and_then(|o| o.columns.get(column.name.as_str()));
            let entry = |class: SecretClass| SecretEntry {
                table: table.clone(),
                column: column.name.as_str().to_owned(),
                declared_type: column.declared_type.clone(),
                class,
                dropped: over.is_some_and(|o| o.drop),
                owner: over.and_then(|o| o.rotation_owner.clone()),
            };

            match classify_name(column.name.as_str()) {
                Some(class) => classified.push(entry(class)),
                None if holds_free_text(&column.ty) => review.push(entry(SecretClass::Credential)),
                None => {}
            }
        }
    }

    classified.sort_by(|a, b| (a.class, &a.table, &a.column).cmp(&(b.class, &b.table, &b.column)));
    review.sort_by(|a, b| (&a.table, &a.column).cmp(&(&b.table, &b.column)));

    RotationInventory {
        classified,
        review,
        tables: names,
    }
}

/// Render `SECRETS-ROTATION.md`.
#[must_use]
pub fn render_markdown(inv: &RotationInventory) -> String {
    let mut md = String::new();
    let w = &mut md;

    let _ = writeln!(w, "# Secret rotation inventory\n");
    let _ = writeln!(
        w,
        "Generated by `salvage secrets` from pinned DDL. Run at incident time, **before any data \
         moves**; nothing here waits on the salvage, and rotation proceeds whether or not the \
         batch ever ships.\n"
    );
    let _ = writeln!(
        w,
        "> **Scope.** The attacker had root, so the scope is every secret the compromised cluster \
         *could* hold -- not the secrets detection happened to match. Columns dropped from the \
         salvage under section 8.7 are **in scope and listed below**: dropping decides what we \
         carry forward, not what the attacker could read. Tables excluded from the salvage are in \
         scope too, and if their DDL is not pinned here, that is a gap in this inventory rather \
         than an absence of risk.\n"
    );

    let _ = writeln!(w, "## Tables covered\n");
    if inv.tables.is_empty() {
        let _ = writeln!(w, "_None. No pinned DDL was found._\n");
    } else {
        for t in &inv.tables {
            let _ = writeln!(w, "- `{t}`");
        }
        let _ = writeln!(w);
    }

    let _ = writeln!(w, "## Columns that hold a secret by name\n");
    if inv.classified.is_empty() {
        let _ = writeln!(
            w,
            "_No column name matched a secret class. This is a weak signal, not an all-clear -- \
             see the review list below._\n"
        );
    } else {
        let _ = writeln!(
            w,
            "| Table | Column | Type | Class | In salvage | Rotation | Owner | Done |"
        );
        let _ = writeln!(w, "| --- | --- | --- | --- | --- | --- | --- | --- |");
        for e in &inv.classified {
            let in_salvage = if e.dropped { "dropped" } else { "carried" };
            let owner = e.owner.as_deref().unwrap_or("**UNASSIGNED**");
            let _ = writeln!(
                w,
                "| `{}` | `{}` | `{}` | {} | {} | {} | {} | ☐ |",
                e.table,
                e.column,
                e.declared_type,
                e.class.label(),
                in_salvage,
                e.class.action(),
                owner
            );
        }
        let _ = writeln!(w);
    }

    let _ = writeln!(w, "## Free-text columns needing a human decision\n");
    let _ = writeln!(
        w,
        "No name match, but the type can hold arbitrary text. A support agent pasting a password \
         into a `notes` column is ordinary, and the attacker read that column too. Decide per \
         column; record the decision.\n"
    );
    if inv.review.is_empty() {
        let _ = writeln!(w, "_None._\n");
    } else {
        let _ = writeln!(w, "| Table | Column | Type | In salvage | Decision |");
        let _ = writeln!(w, "| --- | --- | --- | --- | --- |");
        for e in &inv.review {
            let in_salvage = if e.dropped { "dropped" } else { "carried" };
            let _ = writeln!(
                w,
                "| `{}` | `{}` | `{}` | {} | ☐ in scope / ☐ out |",
                e.table, e.column, e.declared_type, in_salvage
            );
        }
        let _ = writeln!(w);
    }

    let _ = writeln!(w, "## Secrets the salvage itself creates or assumes lost\n");
    let _ = writeln!(w, "| Item | Why | Owner | Done |");
    let _ = writeln!(w, "| --- | --- | --- | --- |");
    for (item, why) in OPERATIONAL_SECRETS {
        let _ = writeln!(w, "| {item} | {why} | **UNASSIGNED** | ☐ |");
    }

    let unassigned = inv.unassigned().len();
    let _ = writeln!(w, "\n## Sign-off\n");
    let _ = writeln!(
        w,
        "`ROTATION_SIGNOFF` gates promotion to the clean bucket. It is withheld while any row \
         above is unchecked.\n"
    );
    let _ = writeln!(
        w,
        "- Classified columns: **{}** ({unassigned} with no named owner)",
        inv.classified.len()
    );
    let _ = writeln!(w, "- Free-text columns to decide: **{}**", inv.review.len());
    let _ = writeln!(
        w,
        "- Operational items: **{}**\n",
        OPERATIONAL_SECRETS.len()
    );
    let _ = writeln!(
        w,
        "Set a rotation owner per column with `rotation_owner` in `overrides/<db>.<table>.toml`."
    );

    md
}

/// Machine-readable counts, for `--json`.
#[must_use]
pub fn summary(inv: &RotationInventory) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    out.insert("tables".to_owned(), inv.tables.len());
    out.insert("classified_columns".to_owned(), inv.classified.len());
    out.insert("review_columns".to_owned(), inv.review.len());
    out.insert("unassigned_owners".to_owned(), inv.unassigned().len());
    out.insert("operational_items".to_owned(), OPERATIONAL_SECRETS.len());
    for class in [
        SecretClass::Credential,
        SecretClass::Token,
        SecretClass::SessionId,
        SecretClass::PasswordHash,
        SecretClass::PrivateKey,
        SecretClass::ConnectionString,
    ] {
        out.insert(
            format!("class.{}", class.label().replace([' ', '/'], "_")),
            inv.classified.iter().filter(|e| e.class == class).count(),
        );
    }
    out
}

/// Write the report into the work dir, returning its path.
pub fn write_report(inv: &RotationInventory, work: &std::path::Path) -> Result<std::path::PathBuf> {
    let path = work.join("SECRETS-ROTATION.md");
    let mut guard = crate::abort::PartialOutput::new(path.with_extension("md.partial"));
    std::fs::write(guard.path(), render_markdown(inv)).map_err(|e| {
        crate::abort::infra::<()>(format!("could not write the rotation inventory: {e}"))
            .unwrap_err()
            .with("path", path.display())
    })?;
    guard.commit_as(&path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clickhouse::ddl::parse_create_table;

    fn table(columns: &str) -> PinnedDdl {
        parse_create_table(&format!(
            "CREATE TABLE app.users ({columns}) ENGINE = MergeTree ORDER BY tuple()"
        ))
        .unwrap()
    }

    #[test]
    fn each_secret_class_is_reachable_by_a_realistic_column_name() {
        for (name, expected) in [
            ("password", SecretClass::Credential),
            ("user_passwd", SecretClass::Credential),
            ("client_secret", SecretClass::Credential),
            ("api_key", SecretClass::Token),
            ("accessToken", SecretClass::Token),
            ("refresh_token", SecretClass::Token),
            ("oauth_state", SecretClass::Token),
            ("session_id", SecretClass::SessionId),
            ("cookie_blob", SecretClass::SessionId),
            ("password_hash", SecretClass::PasswordHash),
            ("private_key", SecretClass::PrivateKey),
            ("tls_cert", SecretClass::PrivateKey),
            ("db_dsn", SecretClass::ConnectionString),
            ("connection_string", SecretClass::ConnectionString),
        ] {
            assert_eq!(classify_name(name), Some(expected), "{name}");
        }
        for benign in ["user_id", "created_at", "amount", "region"] {
            assert_eq!(classify_name(benign), None, "{benign}");
        }
    }

    #[test]
    fn the_more_specific_class_wins_over_the_broader_one() {
        // `password_hash` is a hash to force a reset, not a usable credential; the two have
        // different rotation actions, so ordering in the table is load-bearing.
        assert_eq!(
            classify_name("password_hash"),
            Some(SecretClass::PasswordHash)
        );
        assert_eq!(classify_name("password"), Some(SecretClass::Credential));
        assert_eq!(classify_name("private_key"), Some(SecretClass::PrivateKey));
    }

    #[test]
    fn a_dropped_column_is_still_rotated() {
        // The whole scoping rule in one test. Dropping decides what we carry forward; it says
        // nothing about what the attacker could read, and the attacker had root.
        let ddl = table("`id` UInt64, `api_key` String");
        let mut over = crate::models::Overrides {
            cutoff_column: "id".into(),
            cutoff_value: "0".into(),
            cursor_columns: None,
            page_byte_budget: 1024,
            limits: crate::limits::Limits {
                max_compressed_bytes: 1,
                max_uncompressed_bytes: 1,
                max_expansion_ratio: 1,
                max_rows_per_page: 1,
                max_fields_per_row: 1,
                max_field_bytes: 1,
                max_array_elements: 1,
                max_nesting_depth: 1,
                max_tar_members: 1,
                max_tar_member_bytes: 1,
                max_tar_name_bytes: 1,
                max_decode_rounds: 1,
                max_decode_expansion_ratio: 1,
                wall_clock_secs: 1,
            },
            columns: std::collections::BTreeMap::new(),
        };
        over.columns.insert(
            "api_key".to_owned(),
            crate::models::ColumnOverride {
                class: crate::models::FreedomClass::Closed,
                drop: true,
                pattern: None,
                max_len: None,
                enum_ids: None,
                hex: false,
                rotation_owner: Some("platform-oncall".to_owned()),
            },
        );

        let inv = inventory(&[(ddl, Some(over))]);
        assert_eq!(inv.classified.len(), 1);
        let e = &inv.classified[0];
        assert_eq!(e.column, "api_key");
        assert!(e.dropped, "the column is dropped from the salvage");
        assert_eq!(e.owner.as_deref(), Some("platform-oncall"));

        let md = render_markdown(&inv);
        assert!(md.contains("api_key"), "a dropped column must still appear");
        assert!(md.contains("platform-oncall"));
        assert!(md.contains("dropped"));
    }

    #[test]
    fn a_column_with_no_owner_is_flagged_rather_than_defaulted() {
        let inv = inventory(&[(table("`id` UInt64, `session_token` String"), None)]);
        assert_eq!(inv.unassigned().len(), 1);
        assert!(render_markdown(&inv).contains("UNASSIGNED"));
    }

    #[test]
    fn free_text_hides_inside_composites() {
        // A `Map(String, UInt32)` or a `Nested(..., note String)` can hold a pasted secret just as
        // a bare String can, so the reachability check has to recurse.
        let ddl = table(
            "`id` UInt64, `n` Nested(kind UInt8, note String), `m` Map(String, UInt32), \
             `arr` Array(Nullable(String)), `t` Tuple(UInt8, String), `plain` UInt32",
        );
        let inv = inventory(&[(ddl, None)]);
        let review: Vec<&str> = inv.review.iter().map(|e| e.column.as_str()).collect();
        assert!(review.contains(&"n"), "{review:?}");
        assert!(review.contains(&"m"), "{review:?}");
        assert!(review.contains(&"arr"), "{review:?}");
        assert!(review.contains(&"t"), "{review:?}");
        assert!(
            !review.contains(&"plain"),
            "a UInt32 holds no text: {review:?}"
        );
        assert!(!review.contains(&"id"), "{review:?}");
    }

    #[test]
    fn the_operational_secrets_appear_even_with_no_tables_at_all() {
        // Section A3 names Q1's read-only user explicitly: created for this operation on a host
        // next to the compromised cluster, and compromised from that moment. It is not in anyone's
        // schema, so nothing schema-driven would ever surface it.
        let inv = inventory(&[]);
        let md = render_markdown(&inv);
        assert!(md.contains("read-only user"), "{md}");
        assert!(md.contains("CI"), "{md}");
        assert!(md.contains("No pinned DDL was found"));
    }

    #[test]
    fn the_summary_counts_every_class() {
        let ddl = table(
            "`id` UInt64, `password` String, `password_hash` String, `api_key` String, \
             `session_id` String, `private_key` String, `db_dsn` String",
        );
        let s = summary(&inventory(&[(ddl, None)]));
        assert_eq!(s["classified_columns"], 6);
        assert_eq!(s["unassigned_owners"], 6);
        assert_eq!(s["class.credential"], 1);
        assert_eq!(s["class.password_hash"], 1);
        assert_eq!(s["class.private_key___cert"], 1);
        assert_eq!(s["tables"], 1);
    }

    #[test]
    fn the_report_is_byte_identical_between_runs() {
        // It goes into source control next to the DDL that produced it, so a spurious diff is a
        // reason not to look at the real ones.
        let ddl = table("`id` UInt64, `api_key` String, `session_id` String, `notes` String");
        let a = render_markdown(&inventory(&[(ddl.clone(), None)]));
        let b = render_markdown(&inventory(&[(ddl, None)]));
        assert_eq!(a, b);
    }
}

//! The pinned export settings, and the section 9 import flag set.
//!
//! # The hole this closes
//!
//! Section 13 accepts that the source server chooses what to return. What the source plan never
//! says is that the **ordinary settings path produces a successful partial result**: no error,
//! valid gzip, correct trailer, `gzip -t` passes, and every downstream control is satisfied by it.
//! Section 8.1 audits framing, 8.3 validates values, 9 counts rows against a manifest Q1 itself
//! wrote. Nothing compares what came back to what existed, and section 0 concedes it outright.
//!
//! The attacker is root, so they own the read-only user's settings profile, its constraints, and
//! any row policy on it. Every `*_overflow_mode = 'break'` setting stops reading and returns what
//! it has; `limit`/`offset` inject pagination with no change to our SQL;
//! `additional_table_filters` silently adds a WHERE; a stale replica quietly omits committed rows.
//!
//! # Why pinning works even against a root attacker
//!
//! A profile constraint (`<readonly/>`, `<min>`, `<max>`, `<disallowed>`) or `readonly=1` makes an
//! override raise `SETTING_CONSTRAINT_VIOLATION` / `READONLY`. So either we win the setting and
//! get a complete result, **or we lose it and the query errors**. There is no branch where the
//! query succeeds with a quietly clipped result.
//!
//! This does not defeat a root attacker. It converts every config-based truncation path into a
//! loud failure, forcing them into an active lie -- a row policy, or a patched binary -- which is
//! the residual risk section 13 already accepts.

use crate::abort::{Result, SalvageError, abort};

/// One pinned setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    pub name: &'static str,
    pub value: &'static str,
}

/// A named, ordered set of settings rendered into a `SETTINGS` clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub items: &'static [Setting],
}

const fn s(name: &'static str, value: &'static str) -> Setting {
    Setting { name, value }
}

/// The settings attached to every export query.
///
/// Note the apparent contradiction, which is not one: `limit = 0` does **not** conflict with the
/// explicit `LIMIT` in our own SQL. The *setting* injects a limit when non-zero; zero means "no
/// injected limit", so the `LIMIT` in the query text stands.
pub static EXPORT_SETTINGS: Settings = Settings {
    items: &[
        // -- fail, never truncate ---------------------------------------------------------
        s("read_overflow_mode", "'throw'"),
        s("timeout_overflow_mode", "'throw'"),
        s("result_overflow_mode", "'throw'"),
        s("sort_overflow_mode", "'throw'"),
        s("group_by_overflow_mode", "'throw'"),
        s("set_overflow_mode", "'throw'"),
        s("join_overflow_mode", "'throw'"),
        s("distinct_overflow_mode", "'throw'"),
        // -- no ceilings to hit in the first place -----------------------------------------
        s("max_execution_time", "0"),
        s("max_estimated_execution_time", "0"),
        s("max_rows_to_read", "0"),
        s("max_bytes_to_read", "0"),
        s("max_rows_to_read_leaf", "0"),
        s("max_bytes_to_read_leaf", "0"),
        s("max_result_rows", "0"),
        s("max_result_bytes", "0"),
        s("max_rows_to_sort", "0"),
        s("max_bytes_to_sort", "0"),
        s("max_rows_to_group_by", "0"),
        s("max_columns_to_read", "0"),
        s("max_execution_speed", "0"),
        s("max_execution_speed_bytes", "0"),
        // -- no injected predicates or pagination ------------------------------------------
        s("limit", "0"),
        s("offset", "0"),
        s("additional_table_filters", "{}"),
        s("additional_result_filter", "''"),
        // -- no cached or partial reads ----------------------------------------------------
        s("use_query_cache", "0"),
        s("enable_reads_from_query_cache", "0"),
        s("enable_writes_to_query_cache", "0"),
        s("max_parallel_replicas", "1"),
        s("select_sequential_consistency", "1"),
        s("apply_deleted_mask", "1"),
        // -- determinism -------------------------------------------------------------------
        s("session_timezone", "'UTC'"),
    ],
};

impl Settings {
    /// Render a `SETTINGS` clause. Values are pinned constants from this file and are never
    /// derived from server data, so there is nothing here to escape.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from("SETTINGS ");
        for (i, item) in self.items.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(item.name);
            out.push_str(" = ");
            out.push_str(item.value);
        }
        out
    }

    /// Assert every pinned name exists on this server.
    ///
    /// ClickHouse renames settings across versions
    /// (`allow_experimental_parallel_reading_from_replicas` became `enable_parallel_replicas`, and
    /// others), and a name the server does not recognise is **a setting we silently failed to
    /// pin** -- which is indistinguishable, from the client, from never having pinned it.
    pub fn assert_all_known(&self, server_settings: &[String]) -> Result<()> {
        for item in self.items {
            if !server_settings.iter().any(|s| s == item.name) {
                return abort("pinned setting is unknown to this server")
                    .map_err(|e: SalvageError| e.with("setting", item.name));
            }
        }
        Ok(())
    }
}

/// Section 9's import flags, passed verbatim to `clickhouse-client` for the insert test.
///
/// `input_format_skip_unknown_fields` **defaults to 1**: left alone, extra columns vanish silently
/// and schema drift passes undetected. `with_names_use_header=1` is what catches column
/// reordering. Parallel parsing and async inserts are off so error behaviour and row accounting
/// are deterministic.
///
/// `max_query_size` is deliberately absent: it bounds query text only, not streamed INSERT data.
pub static IMPORT_FLAGS: &[&str] = &[
    "--input_format_with_names_use_header=1",
    "--input_format_skip_unknown_fields=0",
    "--input_format_null_as_default=0",
    "--input_format_tsv_empty_as_default=0",
    "--input_format_defaults_for_omitted_fields=0",
    "--input_format_allow_errors_num=0",
    "--input_format_allow_errors_ratio=0",
    "--input_format_parallel_parsing=0",
    "--async_insert=0",
];

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::abort::ExitCode;

    fn all_names() -> Vec<String> {
        EXPORT_SETTINGS
            .items
            .iter()
            .map(|i| i.name.to_string())
            .collect()
    }

    #[test]
    fn every_overflow_mode_is_throw_not_break() {
        for item in EXPORT_SETTINGS.items {
            if item.name.ends_with("_overflow_mode") {
                assert_eq!(
                    item.value, "'throw'",
                    "{} must throw; 'break' truncates silently",
                    item.name
                );
            }
        }
    }

    #[test]
    fn the_injected_pagination_settings_are_zeroed() {
        for name in ["limit", "offset"] {
            let item = EXPORT_SETTINGS
                .items
                .iter()
                .find(|i| i.name == name)
                .unwrap();
            assert_eq!(item.value, "0", "{name} must not inject pagination");
        }
    }

    #[test]
    fn no_setting_is_pinned_twice() {
        let mut names = all_names();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "a duplicated setting is ambiguous");
    }

    #[test]
    fn render_produces_one_settings_clause() {
        let rendered = EXPORT_SETTINGS.render();
        assert!(rendered.starts_with("SETTINGS "));
        assert!(rendered.contains("read_overflow_mode = 'throw'"));
        assert!(rendered.contains("session_timezone = 'UTC'"));
        assert_eq!(rendered.matches("SETTINGS").count(), 1);
    }

    #[test]
    fn a_server_that_knows_every_name_passes() {
        EXPORT_SETTINGS.assert_all_known(&all_names()).unwrap();
    }

    #[test]
    fn a_renamed_setting_aborts_and_names_itself() {
        // The realistic case: a version bump renamed one setting out from under us.
        let mut names = all_names();
        names.retain(|n| n != "apply_deleted_mask");
        let e = EXPORT_SETTINGS.assert_all_known(&names).unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
        assert!(e.to_string().contains("apply_deleted_mask"), "{e}");
    }

    #[test]
    fn skip_unknown_fields_is_explicitly_disabled() {
        // It defaults to 1; leaving it alone is how schema drift passes undetected.
        assert!(
            IMPORT_FLAGS.contains(&"--input_format_skip_unknown_fields=0"),
            "section 9's 'zero skipped' depends on this flag"
        );
    }
}

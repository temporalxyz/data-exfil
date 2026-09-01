-- The type matrix: one table exercising every type section 8.3 supports, plus every trap it names.
--
-- This file is the *authority* for the columns and their types. Section 4: the allowlist comes from
-- source control, and the server's answer is a cross-check, never the authority. `salvage plan`
-- reads this and then asserts `system.columns` agrees with it; a disagreement aborts.
--
-- In step 3 this file is exercised by a line scan that lifts the type strings out and asserts
-- `parse_type` then `rules_for` succeeds for each. Step 4's restricted CREATE TABLE parser replaces
-- the line scan and takes this file as its input unchanged.
--
-- Deliberately absent, because each is out of scope by section 8.3 and must stay unrepresentable
-- rather than merely unused: Geo types, JSON/Object/Dynamic/Variant, AggregateFunction, Interval,
-- Nothing. `each_out_of_scope_type_aborts_by_name` covers those.

CREATE TABLE typematrix.typematrix
(
    -- Integers, at every width. The 128- and 256-bit rows are the ones native types cannot check.
    `u8`                  UInt8,
    `u16`                 UInt16,
    `u32`                 UInt32,
    `u64`                 UInt64,
    `u128`                UInt128,
    `u256`                UInt256,
    `i8`                  Int8,
    `i16`                 Int16,
    `i32`                 Int32,
    `i64`                 Int64,
    `i128`                Int128,
    -- Asymmetric with u256 on purpose: 2^256-1 has 78 digits, 2^255-1 has 77.
    `i256`                Int256,

    -- Decimals. The magnitude check is what a cast does not do.
    `dec_small`           Decimal(5, 2),
    `dec_wide`            Decimal(76, 20),
    `dec_unscaled`        Decimal(9, 0),

    -- Floats travel as IEEE-754 bit patterns, never as text or JSON numbers.
    `f32`                 Float32,
    `f64`                 Float64,

    `flag`                Bool,

    -- Dates and times. Every DateTime64 scale in scope, including 0, which carries no point at all.
    `d`                   Date,
    `d32`                 Date32,
    `dt`                  DateTime,
    `dt64_0`              DateTime64(0),
    `dt64_3`              DateTime64(3),
    `dt64_6`              DateTime64(6),
    `dt64_9`              DateTime64(9),

    -- Non-contiguous enum ids, including a negative one. Ids are carried; labels never are.
    `status`              Enum8('ok' = 1, 'warn' = 4, 'error' = -3, 'unknown' = 100),
    `region`              Enum16('emea' = 1000, 'apac' = -2000),

    -- Strings. `ident` is Closed and gets an exact per-column regex from the overrides;
    -- `body` is the one Open column in the table and is named and justified there.
    `ident`               String,
    `body`                String,
    `nullable_text`       Nullable(String),
    `low_card`            LowCardinality(String),
    -- Section 12 item 1 names this one explicitly.
    `low_card_nullable`   LowCardinality(Nullable(String)),

    -- Fixed-width bytes export as hex, two nybbles per byte.
    `digest`              FixedString(16),
    `blob`                FixedString(32),

    `id`                  UUID,
    `addr4`               IPv4,
    `addr6`               IPv6,

    -- Composites. `Array(Float64)` carries hex bit-strings, not JSON numbers.
    `samples`             Array(Float64),
    `counts`              Array(UInt32),
    -- Section 12 item 1 names this one explicitly.
    `optional_ids`        Array(Nullable(UInt8)),
    `labels`              Map(String, UInt32),
    `pair`                Tuple(UInt8, String),

    -- Nested flattens to one parallel Array per field; all of them must be equal length per row.
    `events`              Nested(kind UInt8, at DateTime, note String),

    -- Dropped by section 11 and by the overrides. Present here because the pinned DDL is the
    -- authority for what the table *is*, and section 8.7's removal is by column and recorded --
    -- a column absent from the DDL and a column dropped in the overrides are different facts.
    `source_url`          String,
    `attachment_path`     String,
    `render_template`     String,
    `payload_serialized`  String,

    -- The cutoff column. Pinned in the overrides, never chosen from server data.
    `ts`                  DateTime
)
ENGINE = MergeTree
ORDER BY (`ts`, `id`)

//! Section 8.3: the per-type export form and validation bounds, as data.
//!
//! This is the file with the largest blast radius in the crate. Four modules read their behaviour
//! out of it -- `export/plan.rs` takes the export expression, `audit/bounds.rs` takes the
//! validator, `clickhouse/quarantine.rs` takes the quarantine type, and `clickhouse/ddl.rs` takes
//! the parser -- so a permissive default here does not degrade the tool, it silently voids it.
//!
//! # The source table, verbatim
//!
//! Transcribed 1 Sep 2026 from pages 10-12 of the Selective ClickHouse Data Salvage Plan (v-final,
//! 25 Aug 2026) via `pdftotext -layout`. Reproduced here so the rule and its authority travel
//! together; an earlier reconstruction of this table by column position was wrong in four places.
//!
//! > **8.3 Types.** Decode before validating. Any column without a written contract is out of
//! > scope -- generic JSON conversion is not a fallback.
//!
//! ```text
//! Type                  Export as                     Validate
//!
//! UInt8/16/32/64        decimal                       ^\d{1,20}$ + range
//! Int8/16/32/64         decimal                       ^-?\d{1,19}$ + range
//! UInt128 / Int128      decimal                       ^\d{1,39}$ / ^-?\d{1,39}$ + range
//! UInt256               decimal                       ^\d{1,78}$ + range
//! Int256                decimal                       ^-?\d{1,77}$ + range
//! Decimal(P,S)          decimal                       ^-?\d+(\.\d{1,S})?$ + abs(v) < 10^(P-S)
//! Float32               hex of IEEE-754 bits          ^[0-9a-fA-F]{8}$
//! Float64               hex of IEEE-754 bits          ^[0-9a-fA-F]{16}$
//! Bool                  0 or 1                        exactly 0 or 1
//! Date / Date32         toString(c)                   ^\d{4}-\d{2}-\d{2}$ + range
//! DateTime              toUnixTimestamp(c)            integer + range
//! DateTime64(N)         toString(c), UTC pinned       see scale table below
//! Enum8 / Enum16        CAST(c AS Int16)              id in source-controlled set
//! String -- identifier  as-is                         exact per-column regex
//! String -- free text   as-is                         UTF-8, length cap,
//!                                                     no [\x00-\x08\x0B\x0C\x0E-\x1F]
//! Nullable(String)      as-is, \N null                as above; null != empty
//! FixedString(N)        hex(c)                        ^[0-9a-fA-F]{2N}$
//! blob / bytes          hex(c)                        drop by default
//! UUID                  as-is                         canonical UUID form
//! IPv4 / IPv6           as-is                         parses; re-emitted canonically
//! LowCardinality(T)     T's rule                      T's rule
//! Tuple(...)            flattened to one column per   each element under its own rule
//!                       element
//! Map(K,V)              two parallel arrays, keys     equal length; elements under K/V rules
//!                       sorted
//! Array(T)              JSON array of T's export      count cap, depth cap, each element as T
//!                       form
//! Nested                flattened parallel arrays     all arrays in the group equal length
//!                                                     per row
//! Geo types             --                            out of scope unless a per-column
//!                                                     contract is written
//! JSON/Object/Dynamic/  --                            out of scope
//! Variant
//! AggregateFunction(..) --                            out of scope; recreate from base rows
//! URL, filename, path,  --                            drop (11)
//! template, script,
//! serialized object
//! ```
//!
//! > Floats travel as bits, not text. Exporting the IEEE-754 bit pattern makes NaN, +-Inf, -0.0 and
//! > every rounding edge exact and unambiguous, and removes the JSON denormal trap entirely -- JSON
//! > encoding turns NaN and +-Inf into an identical null, which reads back as zero, so a null count
//! > sees nothing and the value is silently wrong. `Array(Float64)` therefore carries hex
//! > bit-strings, not JSON numbers.
//!
//! `DateTime64(N)` by scale. UTC pinned on export; exactly N fractional digits, no more, no less:
//!
//! ```text
//! N      Validation
//! 0      ^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$
//! 1-9    ^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{N}$
//! ```
//!
//! > A precision mismatch on re-parse yields a 1970 date, not a rounding error, so the digit count
//! > is checked exactly rather than loosely.
//!
//! **Note the shape of the N=0 row: there is no decimal point at all**, not "a point followed by
//! zero digits". Getting this wrong rejects every valid `DateTime64(0)` value, and the naive
//! `\.\d{0}` spelling accepts a bare trailing dot. It is the reason [`Validator::DateTime64`]
//! branches on the scale rather than generating a pattern.
//!
//! > Dates need a range check, not just a regex. `2026-02-30` parses and silently becomes
//! > `2026-03-02`; `2026-13-45` becomes `1970-01-01`. Decimals need an explicit magnitude check --
//! > casts do not catch decimal overflow, and an out-of-range value is stored as-is.
//!
//! > Enum ids, never labels. The label is an arbitrary string from attacker-controlled DDL; the id
//! > is a number. Carry the number and apply the source-controlled mapping on the clean side, so no
//! > attacker-authored string enters through the enum path.
//!
//! Section 8.2 adds one export-policy line that belongs here rather than with the escapes:
//!
//! > Prefer hex for arbitrary strings and blobs -- it removes delimiter, control-byte and escape
//! > ambiguity entirely, and is the default choice wherever a column allows it.
//!
//! That is why [`ExportExpr::HexBytes`] is reachable for `String` and not only for `FixedString`;
//! the per-column `hex` flag in `ColumnOverride` selects it.
//!
//! # Where this file goes beyond the source
//!
//! Two deliberate extensions, marked so a reviewer can see the seam rather than having to diff
//! against the PDF.
//!
//! SOURCE AMBIGUOUS: the table has only a `Nullable(String)` row. This module generalises to
//! `Nullable(T)` for every supported `T`, applying `T`'s rule to the non-null case and treating
//! `\N` as the only null spelling. That is strictly more coverage than the document specifies and
//! cannot be less safe, but it is our extension and not the document's.
//!
//! SOURCE AMBIGUOUS: the table has no `DateTime(tz)` variant, only `DateTime` ->
//! `toUnixTimestamp(c)`. A unix timestamp is timezone-free, and addition A1 pins
//! `session_timezone = 'UTC'` on every export query, so the parameterised spelling is accepted at
//! parse time and then ignored -- the export form does not vary with it.
//!
//! # Why rules are data and not a trait
//!
//! [`TypeRules`] is `Serialize + Debug + PartialEq`, so the exact rule set applied to every column
//! is embedded in `plan.json` and golden-tested. A `Box<dyn ColumnType>` could be none of those.
//! Dispatch would buy nothing either: the set of ClickHouse types is closed and known at compile
//! time.
//!
//! The single [`rules_for`] match emits the export form and the validator **together**. Drift
//! between those two halves is the bug this shape exists to prevent: export emitting a form that
//! bounds does not accept, or -- worse -- one that it does.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use num_bigint::{BigInt, BigUint};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::Date;
use time::macros::format_description;

use crate::abort::{Result, SalvageError, abort};
use crate::limits::OrOverflow;

// -- identifiers -------------------------------------------------------------------------------

/// A column identifier that has been validated at the boundary and may be rendered into SQL.
///
/// Same discipline `TableRef` and `BatchId` already apply in `cli.rs`: validate once where the
/// value enters, then let every downstream function take the parsed type rather than a `String` it
/// has to re-check. Nothing constructs SQL text from an unvalidated name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Ident(String);

/// Deserialization goes through [`Ident::new`], never around it.
///
/// Hand-written rather than derived on purpose. A derived impl would set the private field
/// directly and let a hand-edited `plan.json` put arbitrary text somewhere that is rendered into
/// SQL -- which is the one thing this newtype exists to prevent. Routing through the constructor
/// means the charset check holds on every path a value can arrive by.
impl<'de> Deserialize<'de> for Ident {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::new(&raw).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl Ident {
    /// `^[A-Za-z0-9_]{1,64}$`. Deliberately narrower than ClickHouse permits: a backtick-quoted
    /// identifier can legally contain a backtick, and we would rather refuse an exotic column name
    /// than reason about escaping one from a compromised server.
    pub fn new(name: &str) -> Result<Self> {
        let ok = !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !ok {
            return abort("column identifier is not in the permitted charset")
                .map_err(|e: SalvageError| e.with("identifier", name.escape_debug()));
        }
        Ok(Self(name.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Backtick-quoted for SQL. Safe without escaping precisely because [`Ident::new`] already
    /// excluded every character that would need it.
    #[must_use]
    pub fn quoted(&self) -> String {
        format!("`{}`", self.0)
    }
}

// -- the type model ----------------------------------------------------------------------------

/// Integer widths, in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IntWidth {
    W8,
    W16,
    W32,
    W64,
    W128,
    W256,
}

impl IntWidth {
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::W8 => 8,
            Self::W16 => 16,
            Self::W32 => 32,
            Self::W64 => 64,
            Self::W128 => 128,
            Self::W256 => 256,
        }
    }

    const fn suffix(self) -> &'static str {
        match self {
            Self::W8 => "8",
            Self::W16 => "16",
            Self::W32 => "32",
            Self::W64 => "64",
            Self::W128 => "128",
            Self::W256 => "256",
        }
    }
}

/// Float widths. Only the two ClickHouse has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FloatWidth {
    F32,
    F64,
}

impl FloatWidth {
    const fn bits(self) -> u32 {
        match self {
            Self::F32 => 32,
            Self::F64 => 64,
        }
    }

    /// Nybbles in the hex bit-string: 8 for Float32, 16 for Float64.
    const fn nybbles(self) -> u32 {
        match self {
            Self::F32 => 8,
            Self::F64 => 16,
        }
    }
}

/// The shape of a declared column type.
///
/// Closed set, no catch-all. An unmodelled spelling is a finding at [`parse_type`], and an
/// unmodelled *supported* spelling is impossible because [`rules_for`] has no `_ =>` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClickHouseType {
    UInt(IntWidth),
    Int(IntWidth),
    Float(FloatWidth),
    /// `P` total significant digits, `S` after the point. `P >= S` is enforced at parse time.
    Decimal {
        p: u32,
        s: u32,
    },
    Bool,
    String,
    FixedString(u32),
    Date,
    Date32,
    /// The optional timezone parses and is then ignored; see the SOURCE AMBIGUOUS note above.
    DateTime,
    DateTime64 {
        scale: u8,
    },
    Uuid,
    Ipv4,
    Ipv6,
    /// Ids are carried as `i16` for both widths because both export as `CAST(c AS Int16)`. An
    /// `Enum8` id outside `i8` range is refused at parse time.
    Enum8(Vec<(String, i16)>),
    Enum16(Vec<(String, i16)>),
    Nullable(Box<Self>),
    LowCardinality(Box<Self>),
    Array(Box<Self>),
    Map(Box<Self>, Box<Self>),
    Tuple(Vec<Self>),
    /// A column group, not a scalar type. ClickHouse stores `Nested(a T, b U)` as one parallel
    /// `Array` per field, which is what the source table's "flattened parallel arrays" describes.
    Nested(Vec<(Ident, Self)>),
}

impl ClickHouseType {
    /// The canonical spelling, which must round-trip through [`parse_type`].
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::UInt(w) => format!("UInt{}", w.suffix()),
            Self::Int(w) => format!("Int{}", w.suffix()),
            Self::Float(FloatWidth::F32) => "Float32".to_owned(),
            Self::Float(FloatWidth::F64) => "Float64".to_owned(),
            Self::Decimal { p, s } => format!("Decimal({p}, {s})"),
            Self::Bool => "Bool".to_owned(),
            Self::String => "String".to_owned(),
            Self::FixedString(n) => format!("FixedString({n})"),
            Self::Date => "Date".to_owned(),
            Self::Date32 => "Date32".to_owned(),
            Self::DateTime => "DateTime".to_owned(),
            Self::DateTime64 { scale } => format!("DateTime64({scale})"),
            Self::Uuid => "UUID".to_owned(),
            Self::Ipv4 => "IPv4".to_owned(),
            Self::Ipv6 => "IPv6".to_owned(),
            Self::Enum8(v) => render_enum("Enum8", v),
            Self::Enum16(v) => render_enum("Enum16", v),
            Self::Nullable(t) => format!("Nullable({})", t.canonical()),
            Self::LowCardinality(t) => format!("LowCardinality({})", t.canonical()),
            Self::Array(t) => format!("Array({})", t.canonical()),
            Self::Map(k, v) => format!("Map({}, {})", k.canonical(), v.canonical()),
            Self::Tuple(items) => {
                let inner: Vec<String> = items.iter().map(Self::canonical).collect();
                format!("Tuple({})", inner.join(", "))
            }
            Self::Nested(fields) => {
                let inner: Vec<String> = fields
                    .iter()
                    .map(|(n, t)| format!("{} {}", n.as_str(), t.canonical()))
                    .collect();
                format!("Nested({})", inner.join(", "))
            }
        }
    }
}

fn render_enum(name: &str, pairs: &[(String, i16)]) -> String {
    let mut out = String::from(name);
    out.push('(');
    for (i, (label, id)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        // The label is attacker-authored DDL. It is reproduced here only so the canonical form
        // round-trips; it never reaches a comparison, and never reaches SQL we send.
        let _ = write!(out, "'{}' = {id}", label.replace('\'', "\\'"));
    }
    out.push(')');
    out
}

// -- the static pattern table ---------------------------------------------------------------

/// A fixed, parameter-free pattern from the section 8.3 table.
///
/// Only patterns with no type parameter live here. `Decimal(P,S)`, `DateTime64(N)` and
/// `FixedString(N)` want a pattern whose text depends on the parameter, and generating those at
/// run time would mean either compiling a regex per column or caching dynamically-built patterns.
/// Both are avoided: those three get a [`Validator`] variant carrying their numbers and a
/// hand-written checker, so **no regex is ever compiled while rows are streaming.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pattern {
    /// `^\d{1,20}$` -- UInt8/16/32/64.
    UnsignedTo20,
    /// `^-?\d{1,19}$` -- Int8/16/32/64.
    SignedTo19,
    /// `^\d{1,39}$` -- UInt128.
    UnsignedTo39,
    /// `^-?\d{1,39}$` -- Int128.
    SignedTo39,
    /// `^\d{1,78}$` -- UInt256.
    UnsignedTo78,
    /// `^-?\d{1,77}$` -- Int256. Asymmetric with UInt256 on purpose: 2^256-1 has 78 digits,
    /// 2^255-1 has 77.
    SignedTo77,
    /// `^\d{4}-\d{2}-\d{2}$` -- Date and Date32, before the calendar check.
    CalendarDate,
    /// `^-?\d{1,20}$` -- DateTime as a unix timestamp, before the range check.
    UnixSeconds,
    /// Canonical 8-4-4-4-12 UUID.
    Uuid,
}

/// The table itself. Order is irrelevant; [`Pattern::index`] is the authority.
const PATTERNS: &[(Pattern, &str)] = &[
    (Pattern::UnsignedTo20, r"^\d{1,20}$"),
    (Pattern::SignedTo19, r"^-?\d{1,19}$"),
    (Pattern::UnsignedTo39, r"^\d{1,39}$"),
    (Pattern::SignedTo39, r"^-?\d{1,39}$"),
    (Pattern::UnsignedTo78, r"^\d{1,78}$"),
    (Pattern::SignedTo77, r"^-?\d{1,77}$"),
    (Pattern::CalendarDate, r"^\d{4}-\d{2}-\d{2}$"),
    (Pattern::UnixSeconds, r"^-?\d{1,20}$"),
    (
        Pattern::Uuid,
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    ),
];

impl Pattern {
    /// Index into [`PATTERNS`]. Spelled as an explicit match rather than an `as` cast, because
    /// `as_conversions` is denied in this module and a silently-wrong discriminant here would
    /// apply the wrong bound to a column.
    const fn index(self) -> usize {
        match self {
            Self::UnsignedTo20 => 0,
            Self::SignedTo19 => 1,
            Self::UnsignedTo39 => 2,
            Self::SignedTo39 => 3,
            Self::UnsignedTo78 => 4,
            Self::SignedTo77 => 5,
            Self::CalendarDate => 6,
            Self::UnixSeconds => 7,
            Self::Uuid => 8,
        }
    }

    /// The compiled regex. Compiled once for the whole process.
    fn regex(self) -> &'static Regex {
        static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
        let all = COMPILED.get_or_init(|| {
            PATTERNS
                .iter()
                .map(|(p, src)| {
                    Regex::new(src).unwrap_or_else(|e| {
                        panic!("section 8.3 pattern {p:?} does not compile: {src} -- {e}")
                    })
                })
                .collect()
        });
        let i = self.index();
        // `every_pattern_in_the_table_compiles` and `the_pattern_table_is_indexed_consistently`
        // together make this unreachable; both are mandatory tests, not optional ones.
        &all[i]
    }

    fn source(self) -> &'static str {
        PATTERNS[self.index()].1
    }

    fn check(self, s: &str) -> Result<()> {
        if self.regex().is_match(s) {
            return Ok(());
        }
        abort("value does not match its section 8.3 pattern").map_err(|e: SalvageError| {
            e.with("pattern", self.source())
                .with("value", s.escape_debug())
        })
    }
}

// -- value ranges ------------------------------------------------------------------------------

/// An inclusive integer range, held at arbitrary precision.
///
/// `num-bigint` rather than a native type because `Int128`, `UInt256` and `Decimal(76, s)` do not
/// fit one, and because a bounds validator that silently narrows is the exact failure this crate
/// exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueRange {
    #[serde(
        serialize_with = "bigint_as_string",
        deserialize_with = "bigint_from_string"
    )]
    pub min: BigInt,
    #[serde(
        serialize_with = "bigint_as_string",
        deserialize_with = "bigint_from_string"
    )]
    pub max: BigInt,
}

/// A 256-bit bound cannot survive a JSON number, so both directions go through a decimal string.
/// If this ever regresses to a native numeric type the reviewable artifact silently stops being
/// reviewable, which is why `a_range_serializes_as_a_decimal_string_not_a_lossy_number` asserts on
/// the wire form rather than on a round-trip alone.
fn bigint_as_string<S: Serializer>(v: &BigInt, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

fn bigint_from_string<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<BigInt, D::Error> {
    let raw = String::deserialize(d)?;
    // Same ordering rule as the row path: `num-bigint` accepts a leading `+` and silently ignores
    // `_` separators, so the shape is screened before the parser is handed the bytes.
    if raw.is_empty()
        || !raw
            .strip_prefix('-')
            .unwrap_or(&raw)
            .bytes()
            .all(|b| b.is_ascii_digit())
    {
        return Err(serde::de::Error::custom(
            "range bound is not a plain decimal integer",
        ));
    }
    raw.parse().map_err(serde::de::Error::custom)
}

/// `2^bits`, and the signed/unsigned bounds derived from it.
///
/// The whole function is the scoped escape from `arithmetic_side_effects`. Arbitrary-precision
/// arithmetic has no overflow to guard against -- that lint exists to catch a wrap, and `BigUint`
/// does not wrap -- so the allow is sound here and nowhere else in the file.
///
/// The parenthesisation is load-bearing. `BigUint::from(1u8) << bits - 1u32` parses as
/// `1 << (bits - 1)` because `-` binds tighter than `<<`, which would make every unsigned upper
/// bound exactly half its true value. That bug is silent, and it is why
/// `uint256_max_is_the_literal_decimal_string` asserts against a hand-written constant.
#[allow(clippy::arithmetic_side_effects)]
fn power_of_two(bits: u32) -> BigUint {
    BigUint::from(1u8) << bits
}

#[allow(clippy::arithmetic_side_effects)]
fn unsigned_range(bits: u32) -> ValueRange {
    ValueRange {
        min: BigInt::from(0u8),
        max: BigInt::from(power_of_two(bits) - 1u32),
    }
}

#[allow(clippy::arithmetic_side_effects)]
fn signed_range(bits: u32) -> Result<ValueRange> {
    let half = power_of_two(bits.checked_sub(1).or_overflow("int width - 1")?);
    let magnitude = BigInt::from(half);
    Ok(ValueRange {
        min: -magnitude.clone(),
        max: magnitude - 1u32,
    })
}

/// `10^exp`, for the decimal magnitude check. Same reasoning as [`power_of_two`].
#[allow(clippy::arithmetic_side_effects)]
fn power_of_ten(exp: u32) -> BigUint {
    BigUint::from(10u32).pow(exp)
}

// -- validators --------------------------------------------------------------------------------

/// What a decoded field must satisfy to be accepted.
///
/// Split deliberately: [`Validator::Matches`] covers every parameter-free pattern via the static
/// table, and each parameterised type gets its own variant carrying its numbers. That is what
/// keeps regex compilation out of the row loop and turns the `DateTime64` scale trap into an
/// integer comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Validator {
    /// A fixed pattern, optionally followed by an inclusive range check.
    Matches {
        pattern: Pattern,
        range: Option<ValueRange>,
    },
    /// `^-?\d+(\.\d{1,S})?$` plus `abs(v) < 10^(P-S)`.
    ///
    /// The magnitude half is not redundant with the pattern: `Decimal(5,2)` accepts `1000.00` on
    /// shape and must still reject it on magnitude. Section 8.3 is explicit that a cast will not
    /// catch this -- "an out-of-range value is stored as-is".
    DecimalPs {
        p: u32,
        s: u32,
    },
    /// `^[0-9a-fA-F]{n}$` with an exact nybble count. Float bit-strings and `FixedString(N)`.
    HexExact {
        nybbles: u32,
    },
    /// `0` or `1`, and nothing else. Not "truthy".
    Bool,
    /// A calendar date with a real month-length and leap-year check, then an inclusive range.
    CalendarDate {
        min: DateBound,
        max: DateBound,
    },
    /// An integer unix timestamp within the type's representable window.
    UnixSeconds {
        min: i64,
        max: i64,
    },
    /// `YYYY-MM-DD HH:MM:SS` plus, for scale 1-9 only, a point and exactly `scale` digits.
    DateTime64 {
        scale: u8,
    },
    /// An enum id from the source-controlled set. Ids, never labels.
    EnumId {
        ids: Vec<i16>,
    },
    /// Canonical UUID, re-emitted lowercase.
    Uuid,
    Ipv4,
    Ipv6,
    /// A per-column exact pattern for a Closed or Constrained string column.
    ///
    /// Compiled on construction, not per row. Held as its source text so `TypeRules` stays
    /// `PartialEq` and serializable; the compiled form lives in the same `OnceLock`-style cache as
    /// the static table.
    ColumnPattern {
        source: String,
    },
    /// Section 8.3 free text: UTF-8, a length cap, and no C0 controls other than the three the
    /// escape grammar already round-trips.
    FreeText {
        max_len: Option<u32>,
    },
    /// A JSON array whose elements each satisfy the inner validator.
    JsonArray {
        inner: Box<Validator>,
        max_elements: u32,
    },
}

/// A calendar bound, stored as its ISO text so [`Validator`] stays serializable and comparable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DateBound(pub String);

const DATE_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]");

/// Control bytes rejected inside a field, per section 8.3's
/// `[\x00-\x08\x0B\x0C\x0E-\x1F]`.
///
/// Note what is *absent*: `\t` (0x09), `\n` (0x0A) and `\r` (0x0D). Those are not permitted raw
/// either -- `tsv.rs` rejects them at the escape layer, and by the time a value reaches here it has
/// been decoded, so a tab in a decoded value came from a canonical `\t` and is legitimate content.
const fn is_forbidden_control(b: u8) -> bool {
    matches!(b, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F)
}

impl Validator {
    /// Check one decoded field value.
    ///
    /// Takes bytes, not `&str`: everything upstream of here is attacker-authored, and the UTF-8
    /// decision is part of the check rather than an assumption made before it.
    pub fn check(&self, value: &[u8]) -> Result<()> {
        let s = std::str::from_utf8(value).map_err(|e| {
            SalvageError::Abort {
                reason: "value is not valid UTF-8".to_owned(),
                context: Vec::new(),
            }
            .with("error", e)
        })?;

        match self {
            Self::Matches { pattern, range } => {
                pattern.check(s)?;
                if let Some(r) = range {
                    check_int_range(s, r)?;
                }
                Ok(())
            }
            Self::DecimalPs { p, s: scale } => check_decimal(s, *p, *scale),
            Self::HexExact { nybbles } => check_hex_exact(s, *nybbles),
            Self::Bool => {
                if s == "0" || s == "1" {
                    Ok(())
                } else {
                    abort("Bool must be exactly 0 or 1")
                        .map_err(|e: SalvageError| e.with("value", s.escape_debug()))
                }
            }
            Self::CalendarDate { min, max } => check_calendar_date(s, min, max),
            Self::UnixSeconds { min, max } => check_unix_seconds(s, *min, *max),
            Self::DateTime64 { scale } => check_datetime64(s, *scale),
            Self::EnumId { ids } => check_enum_id(s, ids),
            Self::Uuid => Pattern::Uuid.check(s),
            Self::Ipv4 => check_ipv4(s),
            Self::Ipv6 => check_ipv6(s),
            Self::ColumnPattern { source } => check_column_pattern(s, source),
            Self::FreeText { max_len } => check_free_text(value, s, *max_len),
            Self::JsonArray {
                inner,
                max_elements,
            } => check_json_array(s, inner, *max_elements),
        }
    }
}

fn check_int_range(s: &str, range: &ValueRange) -> Result<()> {
    // The pattern already ran, so the parser never sees unscreened bytes. That ordering is not
    // stylistic: `num-bigint` accepts a leading `+` and *silently ignores `_` separators*, so
    // "1_000" would parse as 1000. The regex is the authority; the parser is not.
    let v: BigInt = s.parse().map_err(|e| {
        SalvageError::Abort {
            reason: "value is not an integer".to_owned(),
            context: Vec::new(),
        }
        .with("error", e)
    })?;
    if v < range.min || v > range.max {
        return abort("integer is outside the range of its declared type").map_err(
            |e: SalvageError| {
                e.with("value", s)
                    .with("min", &range.min)
                    .with("max", &range.max)
            },
        );
    }
    Ok(())
}

fn check_decimal(s: &str, p: u32, scale: u32) -> Result<()> {
    let body = s.strip_prefix('-').unwrap_or(s);
    let (int_part, frac_part) = match body.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (body, None),
    };

    let digits_ok = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    if !digits_ok(int_part) {
        return abort("Decimal has no integer digits")
            .map_err(|e: SalvageError| e.with("value", s.escape_debug()));
    }
    match frac_part {
        // Scale 0 admits no point at all, exactly as the N=0 DateTime64 row admits none.
        Some(_) if scale == 0 => {
            return abort("Decimal with scale 0 must have no fractional part")
                .map_err(|e: SalvageError| e.with("value", s.escape_debug()));
        }
        Some(f) => {
            let len = u32::try_from(f.len()).or_overflow("decimal fraction length")?;
            if !digits_ok(f) || len > scale {
                return abort("Decimal fractional digits exceed the declared scale").map_err(
                    |e: SalvageError| e.with("value", s.escape_debug()).with("scale", scale),
                );
            }
        }
        None => {}
    }

    // abs(v) < 10^(P-S). Casts do not catch this; section 8.3 says so in as many words.
    let limit = power_of_ten(p.checked_sub(scale).or_overflow("Decimal P - S")?);
    let magnitude: BigUint = int_part.parse().map_err(|e| {
        SalvageError::Abort {
            reason: "Decimal integer part does not parse".to_owned(),
            context: Vec::new(),
        }
        .with("error", e)
    })?;
    if magnitude >= limit {
        return abort("Decimal magnitude is out of range for its precision").map_err(
            |e: SalvageError| {
                e.with("value", s.escape_debug())
                    .with("precision", p)
                    .with("scale", scale)
                    .with("limit", limit)
            },
        );
    }
    Ok(())
}

fn check_hex_exact(s: &str, nybbles: u32) -> Result<()> {
    let len = u32::try_from(s.len()).or_overflow("hex length")?;
    if len != nybbles || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return abort("value is not the exact hex string its type requires").map_err(
            |e: SalvageError| {
                e.with("expected_nybbles", nybbles)
                    .with("value", s.escape_debug())
            },
        );
    }
    Ok(())
}

fn parse_calendar_date(s: &str) -> Result<Date> {
    // `time` routes (year, month, day) through `from_calendar_date`, which is leap-aware and
    // month-length aware, so 2026-02-30 *fails* here rather than rolling over to 2026-03-02 the
    // way a naive conversion does. Trailing input is rejected too.
    Date::parse(s, DATE_FORMAT).map_err(|e| {
        SalvageError::Abort {
            reason: "date is not a real calendar date".to_owned(),
            context: Vec::new(),
        }
        .with("value", s.escape_debug())
        .with("error", e)
    })
}

fn check_calendar_date(s: &str, min: &DateBound, max: &DateBound) -> Result<()> {
    Pattern::CalendarDate.check(s)?;
    let d = parse_calendar_date(s)?;
    let lo = parse_calendar_date(&min.0)?;
    let hi = parse_calendar_date(&max.0)?;
    if d < lo || d > hi {
        return abort("date is outside the representable range of its declared type")
            .map_err(|e: SalvageError| e.with("value", s).with("min", &min.0).with("max", &max.0));
    }
    Ok(())
}

fn check_unix_seconds(s: &str, min: i64, max: i64) -> Result<()> {
    Pattern::UnixSeconds.check(s)?;
    let v: i64 = s.parse().map_err(|e| {
        SalvageError::Abort {
            reason: "unix timestamp does not parse".to_owned(),
            context: Vec::new(),
        }
        .with("error", e)
    })?;
    if v < min || v > max {
        return abort("unix timestamp is outside the range of its declared type")
            .map_err(|e: SalvageError| e.with("value", v).with("min", min).with("max", max));
    }
    Ok(())
}

/// `DateTime64(N)`, per the scale table on page 11.
///
/// N=0 admits **no decimal point at all**; N=1-9 admit a point and exactly N digits. The whole
/// reason for exactness is quoted in the module header: a precision mismatch on re-parse yields a
/// 1970 date, not a rounding error, so a loose digit count is not a cosmetic problem.
fn check_datetime64(s: &str, scale: u8) -> Result<()> {
    let (stamp, fraction) = match s.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };

    let (date, time) = stamp.split_once(' ').ok_or_else(|| {
        SalvageError::Abort {
            reason: "DateTime64 is not `YYYY-MM-DD HH:MM:SS`".to_owned(),
            context: Vec::new(),
        }
        .with("value", s.escape_debug())
    })?;

    parse_calendar_date(date)?;
    check_wall_clock(time, s)?;

    match (scale, fraction) {
        (0, None) => Ok(()),
        (0, Some(_)) => abort("DateTime64(0) must carry no fractional part")
            .map_err(|e: SalvageError| e.with("value", s.escape_debug())),
        (_, None) => abort("DateTime64 is missing its fractional part")
            .map_err(|e: SalvageError| e.with("value", s.escape_debug()).with("scale", scale)),
        (n, Some(f)) => {
            let want = usize::from(n);
            if f.len() != want || !f.bytes().all(|b| b.is_ascii_digit()) {
                return abort("DateTime64 fractional digits do not match the declared scale")
                    .map_err(|e: SalvageError| {
                        e.with("value", s.escape_debug())
                            .with("scale", n)
                            .with("observed_digits", f.len())
                    });
            }
            Ok(())
        }
    }
}

fn check_wall_clock(time: &str, whole: &str) -> Result<()> {
    let bad = || {
        SalvageError::Abort {
            reason: "DateTime64 time-of-day is not `HH:MM:SS`".to_owned(),
            context: Vec::new(),
        }
        .with("value", whole.escape_debug())
    };
    let mut parts = time.split(':');
    let (h, m, sec) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(m), Some(s), None) => (h, m, s),
        _ => return Err(bad()),
    };
    for part in [h, m, sec] {
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
    }
    let (h, m, sec): (u8, u8, u8) = (
        h.parse().map_err(|_| bad())?,
        m.parse().map_err(|_| bad())?,
        sec.parse().map_err(|_| bad())?,
    );
    // `from_hms` rejects 24:00:00 and a leap second, which is what we want: ClickHouse never emits
    // either, so one appearing is a signal rather than an edge case to accommodate.
    time::Time::from_hms(h, m, sec).map_err(|_| bad())?;
    Ok(())
}

fn check_enum_id(s: &str, ids: &[i16]) -> Result<()> {
    let v: i16 = s.parse().map_err(|_| {
        SalvageError::Abort {
            reason: "enum id is not an Int16".to_owned(),
            context: Vec::new(),
        }
        // A label arriving where an id belongs lands here, which is the intended outcome: the
        // label is attacker-authored DDL and must never reach a comparison.
        .with("value", s.escape_debug())
    })?;
    if !ids.contains(&v) {
        return abort("enum id is not in the source-controlled set")
            .map_err(|e: SalvageError| e.with("value", v).with("permitted", format!("{ids:?}")));
    }
    Ok(())
}

fn check_ipv4(s: &str) -> Result<()> {
    // Rust's parser is strict: no octal, no leading zeros, no shorthand. That strictness is the
    // point -- `010.1.1.1` meaning two different addresses to two different parsers is exactly the
    // ambiguity section 8.2 rejects escapes to avoid.
    let addr: Ipv4Addr = s.parse().map_err(|e| {
        SalvageError::Abort {
            reason: "value is not an IPv4 address".to_owned(),
            context: Vec::new(),
        }
        .with("value", s.escape_debug())
        .with("error", e)
    })?;
    if addr.to_string() != s {
        return abort("IPv4 address is not in canonical form")
            .map_err(|e: SalvageError| e.with("value", s.escape_debug()));
    }
    Ok(())
}

fn check_ipv6(s: &str) -> Result<()> {
    let addr: Ipv6Addr = s.parse().map_err(|e| {
        SalvageError::Abort {
            reason: "value is not an IPv6 address".to_owned(),
            context: Vec::new(),
        }
        .with("value", s.escape_debug())
        .with("error", e)
    })?;
    if addr.to_string() != s {
        return abort("IPv6 address is not in canonical form")
            .map_err(|e: SalvageError| e.with("value", s.escape_debug()));
    }
    Ok(())
}

fn check_column_pattern(s: &str, source: &str) -> Result<()> {
    let re = column_pattern(source)?;
    if re.is_match(s) {
        return Ok(());
    }
    abort("value does not match its pinned per-column pattern")
        .map_err(|e: SalvageError| e.with("pattern", source).with("value", s.escape_debug()))
}

/// Compile-once cache for per-column patterns from `overrides/`.
///
/// Keyed by source text and never evicted. Bounded by the pinned override file, which has one
/// entry per column of one table, so the cache cannot grow with row count -- which is the only
/// property that matters here.
fn column_pattern(source: &str) -> Result<&'static Regex> {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CACHE: OnceLock<Mutex<HashMap<String, &'static Regex>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().map_err(|_| SalvageError::Abort {
        reason: "per-column pattern cache is poisoned".to_owned(),
        context: Vec::new(),
    })?;
    if let Some(re) = guard.get(source) {
        return Ok(re);
    }
    let compiled = Regex::new(source).map_err(|e| {
        SalvageError::Usage {
            reason: "pinned per-column pattern does not compile".to_owned(),
            context: Vec::new(),
        }
        .with("pattern", source)
        .with("error", e)
    })?;
    // Leaked deliberately: the set is bounded by the pinned override file and lives for the whole
    // run, so a 'static reference is honest about the lifetime rather than forcing a clone per row.
    let leaked: &'static Regex = Box::leak(Box::new(compiled));
    guard.insert(source.to_owned(), leaked);
    Ok(leaked)
}

fn check_free_text(raw: &[u8], s: &str, max_len: Option<u32>) -> Result<()> {
    if let Some(cap) = max_len {
        let len = u32::try_from(s.chars().count()).or_overflow("free text length")?;
        if len > cap {
            return abort("free text exceeds its pinned length cap")
                .map_err(|e: SalvageError| e.with("cap", cap).with("observed", len));
        }
    }
    if let Some(pos) = raw.iter().position(|b| is_forbidden_control(*b)) {
        let byte = raw.get(pos).copied().unwrap_or(0);
        return abort("free text contains a forbidden control byte").map_err(|e: SalvageError| {
            e.with("offset", pos).with("byte", format!("0x{byte:02x}"))
        });
    }
    Ok(())
}

fn check_json_array(s: &str, inner: &Validator, max_elements: u32) -> Result<()> {
    let parsed: serde_json::Value = serde_json::from_str(s).map_err(|e| {
        SalvageError::Abort {
            reason: "Array does not parse as JSON".to_owned(),
            context: Vec::new(),
        }
        .with("error", e)
    })?;
    let items = match parsed {
        serde_json::Value::Array(items) => items,
        _ => {
            return abort("Array is not a JSON array")
                .map_err(|e: SalvageError| e.with("value", s.escape_debug()));
        }
    };
    let count = u32::try_from(items.len()).or_overflow("array element count")?;
    if count > max_elements {
        return abort("Array exceeds the section 8.4 element cap")
            .map_err(|e: SalvageError| e.with("cap", max_elements).with("observed", count));
    }
    for (i, item) in items.iter().enumerate() {
        // Elements arrive in whatever JSON form the element's export expression produced -- a
        // string for hex and text forms, a bare number for the decimal forms. Anything else is a
        // shape we did not ask for.
        let text = match item {
            serde_json::Value::String(t) => t.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Null => {
                return abort(
                    "Array element is JSON null; nulls travel as `\\N`, not as JSON null",
                )
                .map_err(|e: SalvageError| e.with("index", i));
            }
            _ => {
                return abort("Array element is not a scalar")
                    .map_err(|e: SalvageError| e.with("index", i));
            }
        };
        inner
            .check(text.as_bytes())
            .map_err(|e| e.with("array_index", i))?;
    }
    Ok(())
}

// -- export expressions ------------------------------------------------------------------------

/// How a column is projected in the `SELECT`.
///
/// An enum, never a `String`. Every piece of SQL text for column projection is produced by
/// [`ExportExpr::render`] and nowhere else, so `export/plan.rs` never concatenates SQL and there is
/// exactly one place to review for injection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportExpr {
    /// The column as the server renders it.
    Identity,
    /// `hex(c)`. Section 8.2's preferred form for arbitrary strings and blobs.
    HexBytes,
    /// `hex(reinterpretAsUInt32|64(c))` -- the IEEE-754 bit pattern, so NaN, +-Inf and -0.0 survive
    /// exactly. Text or JSON would collapse them.
    FloatBits(FloatWidth),
    /// `toString(c)`, with `session_timezone = 'UTC'` pinned by the export settings.
    ToStringUtc,
    /// `toUnixTimestamp(c)`.
    UnixTimestamp,
    /// `CAST(c AS Int16)`. The id, never the label.
    EnumId,
    /// `CAST(c AS UInt8)`, yielding exactly `0` or `1`.
    BoolAsDigit,
    /// One element of a tuple, projected as its own column.
    TupleElement { index: u32, inner: Box<ExportExpr> },
    /// The keys of a map, as a JSON array, ordered by the sorted key.
    MapKeys(Box<ExportExpr>),
    /// The values of a map, as a JSON array, in the order their keys sort to.
    MapValues(Box<ExportExpr>),
    /// `toJSONString(arrayMap(...))` -- a JSON array of the inner form.
    JsonArrayOf(Box<ExportExpr>),
    /// One field of a `Nested` column.
    ///
    /// ClickHouse does not store a `Nested` as a single value: it stores one parallel array per
    /// field, in its own column named `<parent>.<field>`. So the inner expression must render
    /// against **that** column and not against the parent, which does not exist as a readable
    /// column at all.
    NestedField {
        field: Ident,
        inner: Box<ExportExpr>,
    },
}

impl ExportExpr {
    /// Render against a validated column identifier.
    #[must_use]
    pub fn render(&self, col: &Ident) -> String {
        self.render_on(&col.quoted())
    }

    fn render_on(&self, operand: &str) -> String {
        match self {
            Self::Identity => operand.to_owned(),
            Self::HexBytes => format!("hex({operand})"),
            Self::FloatBits(w) => {
                format!("hex(reinterpretAsUInt{}({operand}))", w.bits())
            }
            Self::ToStringUtc => format!("toString({operand})"),
            Self::UnixTimestamp => format!("toUnixTimestamp({operand})"),
            Self::EnumId => format!("CAST({operand} AS Int16)"),
            Self::BoolAsDigit => format!("CAST({operand} AS UInt8)"),
            Self::TupleElement { index, inner } => {
                inner.render_on(&format!("tupleElement({operand}, {index})"))
            }
            // Sorting the *pairs* and then projecting each side is not a stylistic choice.
            // `arraySort(mapKeys(c))` and `mapValues(c)` sorted independently would misalign every
            // row silently -- the keys would be in order and the values would not follow them.
            Self::MapKeys(inner) => format!(
                "toJSONString(arrayMap(x -> {}, {}))",
                inner.render_on("x.1"),
                sorted_pairs(operand)
            ),
            Self::MapValues(inner) => format!(
                "toJSONString(arrayMap(x -> {}, {}))",
                inner.render_on("x.2"),
                sorted_pairs(operand)
            ),
            Self::JsonArrayOf(inner) => format!(
                "toJSONString(arrayMap(x -> {}, {operand}))",
                inner.render_on("x")
            ),
            Self::NestedField { field, inner } => {
                // `operand` is the backtick-quoted parent; the readable column is
                // `parent.field`. Both halves are validated `Ident`s, so re-quoting the joined
                // name needs no escaping -- the charset excluded everything that would.
                let base = operand.trim_matches('`');
                inner.render_on(&format!("`{base}.{}`", field.as_str()))
            }
        }
    }
}

fn sorted_pairs(operand: &str) -> String {
    format!("arraySort(y -> y.1, arrayZip(mapKeys({operand}), mapValues({operand})))")
}

// -- the rule set ------------------------------------------------------------------------------

/// The quarantine column type. Section 10: `String` / `Nullable(String)` only, because values are
/// already contract-validated and holding them as text makes coercion structurally impossible at
/// the import boundary. This is what delivers "zero defaulted rows" -- a `Date` column accepts
/// `2300-01-01` and silently clamps it, a `String` column cannot coerce anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineType {
    String,
    NullableString,
}

impl QuarantineType {
    #[must_use]
    pub const fn sql(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::NullableString => "Nullable(String)",
        }
    }
}

/// One projected output column. Most types produce exactly one; `Tuple`, `Map` and `Nested`
/// produce several, which is what the source table means by "flattened".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportColumn {
    /// Appended to the source column name to make the output name unique. Empty for the ordinary
    /// one-column case.
    pub suffix: String,
    pub expr: ExportExpr,
    pub validator: Validator,
}

/// Everything section 8.3 has to say about one declared column.
///
/// `Serialize + Debug + PartialEq` on purpose: this struct is embedded verbatim in `plan.json`, so
/// the exact bound applied to every column is reviewable on a page before a 100 GB export is
/// attempted, and drift between runs shows up in a diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeRules {
    pub canonical: String,
    pub nullable: bool,
    pub quarantine: QuarantineType,
    /// True for `Map` and `Nested`: every array this column expands to must have the same length
    /// **per row**. That is a row-level cross-column check, so `audit/bounds.rs` owns enforcing it;
    /// this flag is how it knows which columns form a group.
    pub equal_length_group: bool,
    pub columns: Vec<ExportColumn>,
}

/// Default element cap for `Array(T)` when no pinned `Limits` narrows it.
pub const DEFAULT_MAX_ARRAY_ELEMENTS: u32 = 4096;

/// Derive the export form and the validation bounds for a declared type, together.
///
/// The single match is the design. Two separate matches -- one for the export expression, one for
/// the validator -- would drift, and drift here *is* the bug: export emits a form that bounds does
/// not accept, or worse, one that it does.
///
/// `max_array_elements` comes from the pinned `Limits` in `overrides/`; pass
/// [`DEFAULT_MAX_ARRAY_ELEMENTS`] when no override applies.
pub fn rules_for(t: &ClickHouseType, max_array_elements: u32) -> Result<TypeRules> {
    let (columns, equal_length_group, nullable) = expand(t, max_array_elements, false)?;
    let quarantine = if nullable {
        QuarantineType::NullableString
    } else {
        QuarantineType::String
    };
    Ok(TypeRules {
        canonical: t.canonical(),
        nullable,
        quarantine,
        equal_length_group,
        columns,
    })
}

/// Returns `(columns, equal_length_group, nullable)`.
fn expand(
    t: &ClickHouseType,
    max_elems: u32,
    nullable: bool,
) -> Result<(Vec<ExportColumn>, bool, bool)> {
    let one = |expr: ExportExpr, validator: Validator| {
        Ok((
            vec![ExportColumn {
                suffix: String::new(),
                expr,
                validator,
            }],
            false,
            nullable,
        ))
    };

    match t {
        ClickHouseType::UInt(w) => {
            let pattern = match w {
                IntWidth::W8 | IntWidth::W16 | IntWidth::W32 | IntWidth::W64 => {
                    Pattern::UnsignedTo20
                }
                IntWidth::W128 => Pattern::UnsignedTo39,
                IntWidth::W256 => Pattern::UnsignedTo78,
            };
            one(
                ExportExpr::Identity,
                Validator::Matches {
                    pattern,
                    range: Some(unsigned_range(w.bits())),
                },
            )
        }
        ClickHouseType::Int(w) => {
            let pattern = match w {
                IntWidth::W8 | IntWidth::W16 | IntWidth::W32 | IntWidth::W64 => Pattern::SignedTo19,
                IntWidth::W128 => Pattern::SignedTo39,
                IntWidth::W256 => Pattern::SignedTo77,
            };
            one(
                ExportExpr::Identity,
                Validator::Matches {
                    pattern,
                    range: Some(signed_range(w.bits())?),
                },
            )
        }
        ClickHouseType::Float(w) => one(
            ExportExpr::FloatBits(*w),
            Validator::HexExact {
                nybbles: w.nybbles(),
            },
        ),
        ClickHouseType::Decimal { p, s } => {
            one(ExportExpr::Identity, Validator::DecimalPs { p: *p, s: *s })
        }
        ClickHouseType::Bool => one(ExportExpr::BoolAsDigit, Validator::Bool),
        ClickHouseType::String => one(
            // Section 8.2 prefers hex "wherever a column allows it", but the default here stays
            // Identity because a hex-encoded identifier column defeats the exact per-column regex
            // that makes it Closed. `ColumnOverride.hex` opts a column in; that decision is pinned
            // per column rather than guessed per type.
            ExportExpr::Identity,
            Validator::FreeText { max_len: None },
        ),
        ClickHouseType::FixedString(n) => {
            let nybbles = n.checked_mul(2).or_overflow("FixedString(N) * 2")?;
            one(ExportExpr::HexBytes, Validator::HexExact { nybbles })
        }
        ClickHouseType::Date => one(
            ExportExpr::ToStringUtc,
            Validator::CalendarDate {
                min: DateBound("1970-01-01".to_owned()),
                max: DateBound("2149-06-06".to_owned()),
            },
        ),
        ClickHouseType::Date32 => one(
            ExportExpr::ToStringUtc,
            Validator::CalendarDate {
                min: DateBound("1900-01-01".to_owned()),
                max: DateBound("2299-12-31".to_owned()),
            },
        ),
        ClickHouseType::DateTime => one(
            ExportExpr::UnixTimestamp,
            Validator::UnixSeconds {
                min: 0,
                max: 4_294_967_295,
            },
        ),
        ClickHouseType::DateTime64 { scale } => one(
            ExportExpr::ToStringUtc,
            Validator::DateTime64 { scale: *scale },
        ),
        ClickHouseType::Uuid => one(ExportExpr::Identity, Validator::Uuid),
        ClickHouseType::Ipv4 => one(ExportExpr::Identity, Validator::Ipv4),
        ClickHouseType::Ipv6 => one(ExportExpr::Identity, Validator::Ipv6),
        ClickHouseType::Enum8(pairs) | ClickHouseType::Enum16(pairs) => {
            let ids: Vec<i16> = pairs.iter().map(|(_, id)| *id).collect();
            one(ExportExpr::EnumId, Validator::EnumId { ids })
        }
        ClickHouseType::Nullable(inner) => {
            if matches!(
                inner.as_ref(),
                ClickHouseType::Tuple(_)
                    | ClickHouseType::Map(_, _)
                    | ClickHouseType::Nested(_)
                    | ClickHouseType::Array(_)
                    | ClickHouseType::Nullable(_)
            ) {
                return abort("Nullable may not wrap a composite or another Nullable")
                    .map_err(|e: SalvageError| e.with("type", t.canonical()));
            }
            let (cols, group, _) = expand(inner, max_elems, true)?;
            Ok((cols, group, true))
        }
        ClickHouseType::LowCardinality(inner) => expand(inner, max_elems, nullable),
        ClickHouseType::Array(inner) => {
            let (mut cols, _, _) = expand(inner, max_elems, false)?;
            if cols.len() != 1 {
                return abort("Array of a flattened composite is out of scope")
                    .map_err(|e: SalvageError| e.with("type", t.canonical()));
            }
            let element = cols.remove(0);
            one(
                ExportExpr::JsonArrayOf(Box::new(element.expr)),
                Validator::JsonArray {
                    inner: Box::new(element.validator),
                    max_elements: max_elems,
                },
            )
        }
        ClickHouseType::Map(k, v) => {
            let (mut kc, _, _) = expand(k, max_elems, false)?;
            let (mut vc, _, _) = expand(v, max_elems, false)?;
            if kc.len() != 1 || vc.len() != 1 {
                return abort("Map over a flattened composite is out of scope")
                    .map_err(|e: SalvageError| e.with("type", t.canonical()));
            }
            let key = kc.remove(0);
            let val = vc.remove(0);
            Ok((
                vec![
                    ExportColumn {
                        suffix: ".keys".to_owned(),
                        expr: ExportExpr::MapKeys(Box::new(key.expr)),
                        validator: Validator::JsonArray {
                            inner: Box::new(key.validator),
                            max_elements: max_elems,
                        },
                    },
                    ExportColumn {
                        suffix: ".values".to_owned(),
                        expr: ExportExpr::MapValues(Box::new(val.expr)),
                        validator: Validator::JsonArray {
                            inner: Box::new(val.validator),
                            max_elements: max_elems,
                        },
                    },
                ],
                true,
                nullable,
            ))
        }
        ClickHouseType::Tuple(items) => {
            let mut out = Vec::new();
            for (i, item) in items.iter().enumerate() {
                let ordinal = u32::try_from(i)
                    .or_overflow("tuple index")?
                    .checked_add(1)
                    .or_overflow("tuple index + 1")?;
                let (cols, _, _) = expand(item, max_elems, false)?;
                for c in cols {
                    out.push(ExportColumn {
                        suffix: format!(".{ordinal}{}", c.suffix),
                        expr: ExportExpr::TupleElement {
                            index: ordinal,
                            inner: Box::new(c.expr),
                        },
                        validator: c.validator,
                    });
                }
            }
            Ok((out, false, nullable))
        }
        ClickHouseType::Nested(fields) => {
            let mut out = Vec::new();
            for (name, item) in fields {
                // Nested is stored as one parallel Array per field, which is exactly what the
                // source table means by "flattened parallel arrays".
                let arr = ClickHouseType::Array(Box::new(item.clone()));
                let (cols, _, _) = expand(&arr, max_elems, false)?;
                for c in cols {
                    out.push(ExportColumn {
                        suffix: format!(".{}{}", name.as_str(), c.suffix),
                        expr: ExportExpr::NestedField {
                            field: name.clone(),
                            inner: Box::new(c.expr),
                        },
                        validator: c.validator,
                    });
                }
            }
            Ok((out, true, nullable))
        }
    }
}

// -- the parser --------------------------------------------------------------------------------

/// Types the source document places out of scope, each named individually.
///
/// A single "unknown type" message would be a worse control: an operator seeing
/// "no rule for type Point" and an operator seeing "no rule for type Blorp" need different next
/// actions, and section 8.3's own dispositions differ per family. The `reason` text carries the
/// disposition the document specifies.
const OUT_OF_SCOPE: &[(&str, &str)] = &[
    (
        "Point",
        "Geo type: out of scope unless a per-column contract is written",
    ),
    (
        "Ring",
        "Geo type: out of scope unless a per-column contract is written",
    ),
    (
        "Polygon",
        "Geo type: out of scope unless a per-column contract is written",
    ),
    (
        "MultiPolygon",
        "Geo type: out of scope unless a per-column contract is written",
    ),
    (
        "LineString",
        "Geo type: out of scope unless a per-column contract is written",
    ),
    (
        "MultiLineString",
        "Geo type: out of scope unless a per-column contract is written",
    ),
    (
        "JSON",
        "out of scope; generic JSON conversion is not a fallback",
    ),
    (
        "Object",
        "out of scope; generic JSON conversion is not a fallback",
    ),
    (
        "Dynamic",
        "out of scope; generic JSON conversion is not a fallback",
    ),
    (
        "Variant",
        "out of scope; generic JSON conversion is not a fallback",
    ),
    ("AggregateFunction", "out of scope; recreate from base rows"),
    (
        "SimpleAggregateFunction",
        "out of scope; recreate from base rows",
    ),
    ("Interval", "out of scope; no export form is specified"),
    ("Nothing", "out of scope; no export form is specified"),
];

/// Parse a declared ClickHouse type.
///
/// There is no `_ =>` fallback anywhere in this function or in [`rules_for`]. An unmodelled
/// spelling is a finding, because section 8.3 is explicit that a column without a written contract
/// is out of scope and that generic conversion is not a fallback. A permissive default here would
/// not degrade the tool; it would void it.
pub fn parse_type(s: &str) -> Result<ClickHouseType> {
    let s = s.trim();
    let (head, args) = split_head_args(s)?;

    if let Some((_, why)) = OUT_OF_SCOPE
        .iter()
        .find(|(name, _)| head.eq_ignore_ascii_case(name) || head.starts_with("Interval"))
    {
        return abort("no rule for type")
            .map_err(|e: SalvageError| e.with("type", s.escape_debug()).with("reason", *why));
    }

    match (head, args.as_deref()) {
        ("UInt8", None) => Ok(ClickHouseType::UInt(IntWidth::W8)),
        ("UInt16", None) => Ok(ClickHouseType::UInt(IntWidth::W16)),
        ("UInt32", None) => Ok(ClickHouseType::UInt(IntWidth::W32)),
        ("UInt64", None) => Ok(ClickHouseType::UInt(IntWidth::W64)),
        ("UInt128", None) => Ok(ClickHouseType::UInt(IntWidth::W128)),
        ("UInt256", None) => Ok(ClickHouseType::UInt(IntWidth::W256)),
        ("Int8", None) => Ok(ClickHouseType::Int(IntWidth::W8)),
        ("Int16", None) => Ok(ClickHouseType::Int(IntWidth::W16)),
        ("Int32", None) => Ok(ClickHouseType::Int(IntWidth::W32)),
        ("Int64", None) => Ok(ClickHouseType::Int(IntWidth::W64)),
        ("Int128", None) => Ok(ClickHouseType::Int(IntWidth::W128)),
        ("Int256", None) => Ok(ClickHouseType::Int(IntWidth::W256)),
        ("Float32", None) => Ok(ClickHouseType::Float(FloatWidth::F32)),
        ("Float64", None) => Ok(ClickHouseType::Float(FloatWidth::F64)),
        ("Bool" | "Boolean", None) => Ok(ClickHouseType::Bool),
        ("String", None) => Ok(ClickHouseType::String),
        ("UUID", None) => Ok(ClickHouseType::Uuid),
        ("IPv4", None) => Ok(ClickHouseType::Ipv4),
        ("IPv6", None) => Ok(ClickHouseType::Ipv6),
        ("Date", None) => Ok(ClickHouseType::Date),
        ("Date32", None) => Ok(ClickHouseType::Date32),
        // The timezone parses and is then ignored; see the SOURCE AMBIGUOUS note in the header.
        // A unix timestamp is timezone-free and `session_timezone = 'UTC'` is pinned regardless.
        ("DateTime", None | Some(_)) => Ok(ClickHouseType::DateTime),
        ("FixedString", Some(a)) => Ok(ClickHouseType::FixedString(parse_u32(a, "FixedString")?)),
        ("DateTime64", Some(a)) => {
            let parts = split_top_level(a);
            let head_arg = parts.first().copied().unwrap_or("").trim();
            let scale = parse_u32(head_arg, "DateTime64")?;
            if scale > 9 {
                return abort("DateTime64 scale is outside 0-9")
                    .map_err(|e: SalvageError| e.with("scale", scale));
            }
            let scale = u8::try_from(scale).or_overflow("DateTime64 scale")?;
            Ok(ClickHouseType::DateTime64 { scale })
        }
        ("Decimal", Some(a)) => {
            let parts = split_top_level(a);
            let [p, s2] = parts.as_slice() else {
                return abort("Decimal needs exactly two arguments")
                    .map_err(|e: SalvageError| e.with("args", a.escape_debug()));
            };
            decimal(parse_u32(p, "Decimal P")?, parse_u32(s2, "Decimal S")?)
        }
        ("Decimal32", Some(a)) => decimal(9, parse_u32(a, "Decimal32 S")?),
        ("Decimal64", Some(a)) => decimal(18, parse_u32(a, "Decimal64 S")?),
        ("Decimal128", Some(a)) => decimal(38, parse_u32(a, "Decimal128 S")?),
        ("Decimal256", Some(a)) => decimal(76, parse_u32(a, "Decimal256 S")?),
        ("Enum8", Some(a)) => Ok(ClickHouseType::Enum8(parse_enum(a, true)?)),
        ("Enum16" | "Enum", Some(a)) => Ok(ClickHouseType::Enum16(parse_enum(a, false)?)),
        ("Nullable", Some(a)) => Ok(ClickHouseType::Nullable(Box::new(parse_type(a)?))),
        ("LowCardinality", Some(a)) => Ok(ClickHouseType::LowCardinality(Box::new(parse_type(a)?))),
        ("Array", Some(a)) => Ok(ClickHouseType::Array(Box::new(parse_type(a)?))),
        ("Map", Some(a)) => {
            let parts = split_top_level(a);
            let [k, v] = parts.as_slice() else {
                return abort("Map needs exactly two arguments")
                    .map_err(|e: SalvageError| e.with("args", a.escape_debug()));
            };
            Ok(ClickHouseType::Map(
                Box::new(parse_type(k)?),
                Box::new(parse_type(v)?),
            ))
        }
        ("Tuple", Some(a)) => {
            let mut items = Vec::new();
            for part in split_top_level(a) {
                // Named tuple elements (`Tuple(a UInt8, b String)`) are accepted and the name is
                // dropped: the export form flattens positionally, so a name would be decoration.
                items.push(parse_type(strip_field_name(part))?);
            }
            if items.is_empty() {
                return abort("Tuple has no elements")
                    .map_err(|e: SalvageError| e.with("type", s.escape_debug()));
            }
            Ok(ClickHouseType::Tuple(items))
        }
        ("Nested", Some(a)) => {
            let mut fields = Vec::new();
            for part in split_top_level(a) {
                let part = part.trim();
                let (name, ty) = part.split_once(char::is_whitespace).ok_or_else(|| {
                    SalvageError::Abort {
                        reason: "Nested field needs a name and a type".to_owned(),
                        context: Vec::new(),
                    }
                    .with("field", part.escape_debug())
                })?;
                fields.push((Ident::new(name.trim())?, parse_type(ty)?));
            }
            if fields.is_empty() {
                return abort("Nested has no fields")
                    .map_err(|e: SalvageError| e.with("type", s.escape_debug()));
            }
            Ok(ClickHouseType::Nested(fields))
        }
        _ => abort("no rule for type").map_err(|e: SalvageError| {
            e.with("type", s.escape_debug())
                .with("reason", "not in the section 8.3 table")
        }),
    }
}

fn decimal(p: u32, s: u32) -> Result<ClickHouseType> {
    if s > p {
        return abort("Decimal scale exceeds its precision")
            .map_err(|e: SalvageError| e.with("precision", p).with("scale", s));
    }
    if p == 0 || p > 76 {
        return abort("Decimal precision is outside 1-76")
            .map_err(|e: SalvageError| e.with("precision", p));
    }
    Ok(ClickHouseType::Decimal { p, s })
}

/// `Name` or `Name(args)`. Returns the head and the unparsed argument text.
fn split_head_args(s: &str) -> Result<(&str, Option<String>)> {
    let Some(open) = s.find('(') else {
        return Ok((s, None));
    };
    if !s.ends_with(')') {
        return abort("type has an unbalanced parenthesis")
            .map_err(|e: SalvageError| e.with("type", s.escape_debug()));
    }
    let head = s.get(..open).unwrap_or("").trim();
    let last = s.len().checked_sub(1).or_overflow("type length - 1")?;
    let start = open.checked_add(1).or_overflow("paren offset + 1")?;
    let inner = s.get(start..last).unwrap_or("");
    if depth_of(inner) != 0 {
        return abort("type has an unbalanced parenthesis")
            .map_err(|e: SalvageError| e.with("type", s.escape_debug()));
    }
    Ok((head, Some(inner.to_owned())))
}

fn depth_of(s: &str) -> i64 {
    let mut depth: i64 = 0;
    let mut in_quote = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quote => escaped = true,
            '\'' => in_quote = !in_quote,
            '(' if !in_quote => depth = depth.saturating_add(1),
            ')' if !in_quote => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

/// Split on commas that are not inside parentheses or a quoted enum label.
fn split_top_level(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth: i64 = 0;
    let mut in_quote = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quote => escaped = true,
            '\'' => in_quote = !in_quote,
            '(' if !in_quote => depth = depth.saturating_add(1),
            ')' if !in_quote => depth = depth.saturating_sub(1),
            ',' if !in_quote && depth == 0 => {
                out.push(s.get(start..i).unwrap_or("").trim());
                start = i.checked_add(1).unwrap_or(i);
            }
            _ => {}
        }
    }
    out.push(s.get(start..).unwrap_or("").trim());
    out.retain(|p| !p.is_empty());
    out
}

/// `a UInt8` -> `UInt8`. Only strips when the leading word is not itself a type head.
fn strip_field_name(part: &str) -> &str {
    let part = part.trim();
    match part.split_once(char::is_whitespace) {
        Some((first, rest)) if !first.contains('(') && parse_type(first).is_err() => rest.trim(),
        _ => part,
    }
}

fn parse_u32(s: &str, what: &'static str) -> Result<u32> {
    s.trim().parse::<u32>().map_err(|e| {
        SalvageError::Abort {
            reason: "type parameter is not a non-negative integer".to_owned(),
            context: Vec::new(),
        }
        .with("parameter", what)
        .with("value", s.escape_debug())
        .with("error", e)
    })
}

/// `'a' = 1, 'b' = 2`. Ids only ever leave here as numbers.
fn parse_enum(args: &str, narrow: bool) -> Result<Vec<(String, i16)>> {
    let mut out: Vec<(String, i16)> = Vec::new();
    for part in split_top_level(args) {
        let (label, id) = part.rsplit_once('=').ok_or_else(|| {
            SalvageError::Abort {
                reason: "enum entry is not `'label' = id`".to_owned(),
                context: Vec::new(),
            }
            .with("entry", part.escape_debug())
        })?;
        let label = label.trim();
        let label = label
            .strip_prefix('\'')
            .and_then(|l| l.strip_suffix('\''))
            .ok_or_else(|| {
                SalvageError::Abort {
                    reason: "enum label is not single-quoted".to_owned(),
                    context: Vec::new(),
                }
                .with("entry", part.escape_debug())
            })?;
        let id: i16 = id.trim().parse().map_err(|e| {
            SalvageError::Abort {
                reason: "enum id is not an Int16".to_owned(),
                context: Vec::new(),
            }
            .with("entry", part.escape_debug())
            .with("error", e)
        })?;
        if narrow && i8::try_from(id).is_err() {
            return abort("Enum8 id does not fit in an Int8")
                .map_err(|e: SalvageError| e.with("id", id));
        }
        if out.iter().any(|(_, existing)| *existing == id) {
            return abort("enum id is declared twice").map_err(|e: SalvageError| e.with("id", id));
        }
        out.push((label.replace("\\'", "'"), id));
    }
    if out.is_empty() {
        return abort("enum has no entries")
            .map_err(|e: SalvageError| e.with("args", args.escape_debug()));
    }
    Ok(out)
}

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

    fn rules(spec: &str) -> TypeRules {
        let t = parse_type(spec).unwrap_or_else(|e| panic!("{spec} should parse: {e}"));
        rules_for(&t, DEFAULT_MAX_ARRAY_ELEMENTS)
            .unwrap_or_else(|e| panic!("{spec} should have rules: {e}"))
    }

    /// The single validator for a type that projects to exactly one column.
    fn validator(spec: &str) -> Validator {
        let r = rules(spec);
        assert_eq!(r.columns.len(), 1, "{spec} should be one column");
        r.columns[0].validator.clone()
    }

    fn accepts(spec: &str, value: &str) {
        validator(spec)
            .check(value.as_bytes())
            .unwrap_or_else(|e| panic!("{spec} should accept {value:?}: {e}"));
    }

    fn rejects(spec: &str, value: &str) {
        let Err(e) = validator(spec).check(value.as_bytes()) else {
            panic!("{spec} should reject {value:?}");
        };
        assert_eq!(e.exit_code(), ExitCode::Abort, "{spec} / {value:?}");
    }

    // -- 1. the static table ------------------------------------------------------------------

    #[test]
    fn every_pattern_in_the_table_compiles() {
        // Mandatory: there is no `unwrap` on the hot path, so a malformed pattern has to fail a
        // test rather than a run. A pattern table that does not compile is a control that does
        // nothing.
        for (p, src) in PATTERNS {
            Regex::new(src).unwrap_or_else(|e| panic!("{p:?} ({src}) does not compile: {e}"));
        }
    }

    #[test]
    fn the_pattern_table_is_indexed_consistently() {
        // `Pattern::index` is hand-written because `as_conversions` is denied here. A wrong
        // discriminant would silently apply another type's bound, so the mapping is asserted
        // rather than trusted.
        for (i, (p, _)) in PATTERNS.iter().enumerate() {
            assert_eq!(p.index(), i, "{p:?} is at the wrong index");
        }
    }

    // -- 2. out-of-scope types, named individually ---------------------------------------------

    #[test]
    fn each_out_of_scope_type_aborts_by_name() {
        for spec in [
            "Point",
            "Ring",
            "Polygon",
            "MultiPolygon",
            "LineString",
            "MultiLineString",
            "JSON",
            "Object",
            "Dynamic",
            "Variant",
            "AggregateFunction",
            "SimpleAggregateFunction",
            "Interval",
            "IntervalDay",
            "Nothing",
        ] {
            let Err(e) = parse_type(spec) else {
                panic!("{spec} must be out of scope");
            };
            assert_eq!(e.exit_code(), ExitCode::Abort, "{spec}");
            assert!(e.to_string().contains("no rule for type"), "{spec}: {e}");
        }
    }

    #[test]
    fn the_geo_refusal_names_the_per_column_contract_escape_hatch() {
        // Section 8.3 says "out of scope *unless a per-column contract is written*". A flat
        // refusal would misreport the document.
        let e = parse_type("Point").unwrap_err();
        assert!(e.to_string().contains("per-column contract"), "{e}");
    }

    #[test]
    fn the_aggregate_function_refusal_names_its_disposition() {
        let e = parse_type("AggregateFunction").unwrap_err();
        assert!(e.to_string().contains("recreate from base rows"), "{e}");
    }

    #[test]
    fn an_unmodelled_spelling_aborts_rather_than_defaulting() {
        let e = parse_type("Blorp").unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
    }

    // -- 3. round-trip ------------------------------------------------------------------------

    #[test]
    fn canonical_round_trips_for_every_supported_type() {
        for spec in [
            "UInt8",
            "UInt16",
            "UInt32",
            "UInt64",
            "UInt128",
            "UInt256",
            "Int8",
            "Int16",
            "Int32",
            "Int64",
            "Int128",
            "Int256",
            "Float32",
            "Float64",
            "Bool",
            "String",
            "UUID",
            "IPv4",
            "IPv6",
            "Date",
            "Date32",
            "DateTime",
            "FixedString(16)",
            "DateTime64(0)",
            "DateTime64(9)",
            "Decimal(76, 20)",
            "Enum8('a' = 1, 'b' = -3)",
            "Enum16('x' = 1000)",
            "Nullable(String)",
            "LowCardinality(String)",
            "Array(Float64)",
            "Map(String, UInt32)",
            "Tuple(UInt8, String)",
            "Nested(a UInt8, b String)",
        ] {
            let parsed = parse_type(spec).unwrap_or_else(|e| panic!("{spec}: {e}"));
            let canonical = parsed.canonical();
            let reparsed = parse_type(&canonical)
                .unwrap_or_else(|e| panic!("{spec} -> {canonical} did not re-parse: {e}"));
            assert_eq!(parsed, reparsed, "{spec} -> {canonical}");
        }
    }

    // -- 4. accept and reject per type (section 12 item 1) --------------------------------------

    #[test]
    fn integers_accept_their_range_and_reject_one_past_it() {
        accepts("UInt8", "0");
        accepts("UInt8", "255");
        rejects("UInt8", "256");
        rejects("UInt8", "-1");
        accepts("Int8", "-128");
        accepts("Int8", "127");
        rejects("Int8", "128");
        rejects("Int8", "-129");
        accepts("Int64", "-9223372036854775808");
        rejects("Int64", "9223372036854775808");
    }

    #[test]
    fn uint256_max_is_the_literal_decimal_string() {
        // The precedence trap: `BigUint::from(1u8) << 256u32 - 1u32` evaluates as `1 << 255`,
        // because `-` binds tighter than `<<`. That would make this bound exactly half its true
        // value and every oversized UInt256 would pass. Asserted against a hand-written constant
        // so the parenthesisation cannot silently regress.
        const MAX: &str =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let Validator::Matches { range: Some(r), .. } = validator("UInt256") else {
            panic!("UInt256 should carry a range");
        };
        assert_eq!(r.max.to_string(), MAX);
        assert_eq!(r.min.to_string(), "0");
        accepts("UInt256", MAX);
        rejects(
            "UInt256",
            "1157920892373161954235709850086879078532699846656405640394575840079131296399350",
        );
    }

    #[test]
    fn int256_range_is_asymmetric_with_uint256_as_the_source_table_says() {
        let Validator::Matches { pattern: up, .. } = validator("UInt256") else {
            panic!()
        };
        let Validator::Matches { pattern: ip, .. } = validator("Int256") else {
            panic!()
        };
        // 78 digits unsigned, 77 signed. 2^256-1 has 78; 2^255-1 has 77.
        assert_eq!(up, Pattern::UnsignedTo78);
        assert_eq!(ip, Pattern::SignedTo77);
    }

    #[test]
    fn the_regex_screens_the_value_before_num_bigint_sees_it() {
        // `num-bigint` accepts a leading `+` and *silently ignores `_` separators*, so "1_000"
        // would parse as 1000. The pattern is the authority; the parser is not.
        rejects("UInt64", "1_000");
        rejects("UInt64", "+1");
        rejects("UInt64", " 1");
        rejects("UInt64", "1 ");
        rejects("UInt64", "");
    }

    #[test]
    fn dates_are_calendar_checked_not_merely_pattern_checked() {
        accepts("Date", "2024-02-29"); // a real leap day
        rejects("Date", "2026-02-29"); // 2026 is not a leap year
        rejects("Date", "2026-02-30"); // parses and becomes 2026-03-02 under a naive conversion
        rejects("Date", "2026-13-45"); // becomes 1970-01-01 under a naive conversion
        rejects("Date", "2026-1-1"); // not the canonical width
        accepts("Date", "1970-01-01");
        rejects("Date", "1969-12-31"); // below the Date epoch
        rejects("Date", "2150-01-01"); // above the Date ceiling
        accepts("Date32", "1900-01-01"); // Date32 reaches further in both directions
    }

    #[test]
    fn datetime64_scale_zero_carries_no_decimal_point_at_all() {
        // The correction that came out of reading the source: the N=0 row of the scale table is
        // `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$` -- no point, not a point with zero digits.
        accepts("DateTime64(0)", "2026-08-25 12:00:00");
        rejects("DateTime64(0)", "2026-08-25 12:00:00.");
        rejects("DateTime64(0)", "2026-08-25 12:00:00.0");
    }

    #[test]
    fn datetime64_demands_exactly_its_declared_number_of_digits() {
        accepts("DateTime64(3)", "2026-08-25 12:00:00.123");
        rejects("DateTime64(3)", "2026-08-25 12:00:00.1");
        rejects("DateTime64(3)", "2026-08-25 12:00:00.1234");
        rejects("DateTime64(3)", "2026-08-25 12:00:00");
        accepts("DateTime64(9)", "2026-08-25 12:00:00.123456789");
        rejects("DateTime64(9)", "2026-08-25 12:00:00.12345678");
    }

    #[test]
    fn datetime64_validates_the_calendar_and_the_wall_clock() {
        rejects("DateTime64(3)", "2026-02-30 12:00:00.000");
        rejects("DateTime64(3)", "2026-08-25 24:00:00.000");
        rejects("DateTime64(3)", "2026-08-25 12:60:00.000");
        rejects("DateTime64(3)", "2026-08-25T12:00:00.000"); // T separator is not what we export
    }

    #[test]
    fn decimal_rejects_a_magnitude_a_cast_would_not_catch() {
        // Regex-valid, magnitude-invalid. Section 8.3: "casts do not catch decimal overflow, and
        // an out-of-range value is stored as-is." This is the whole reason the check exists.
        accepts("Decimal(5, 2)", "999.99");
        rejects("Decimal(5, 2)", "1000.00");
        accepts("Decimal(5, 2)", "-999.99");
        rejects("Decimal(5, 2)", "-1000.00");
        rejects("Decimal(5, 2)", "1.234"); // more digits than the scale
        accepts("Decimal(5, 2)", "1.2");
        accepts("Decimal(5, 2)", "1");
        rejects("Decimal(5, 0)", "1.0"); // scale 0 admits no point, as with DateTime64(0)
        accepts("Decimal(76, 20)", "1.5");
    }

    #[test]
    fn decimal_scale_may_not_exceed_its_precision() {
        assert!(parse_type("Decimal(2, 5)").is_err());
        assert!(parse_type("Decimal(0, 0)").is_err());
        assert!(parse_type("Decimal(77, 1)").is_err());
    }

    #[test]
    fn floats_travel_as_bits_so_every_special_value_stays_distinct() {
        // JSON collapses NaN and +-Inf to an identical null that reads back as zero. Five values,
        // five distinct bit strings, no collisions.
        let bits = |f: f64| format!("{:016X}", f.to_bits());
        let all = [
            bits(f64::NAN),
            bits(f64::INFINITY),
            bits(f64::NEG_INFINITY),
            bits(-0.0),
            bits(0.0),
        ];
        let mut unique = all.clone().to_vec();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 5, "bit patterns collided: {all:?}");
        for b in &all {
            accepts("Float64", b);
        }
        rejects("Float64", "NaN");
        rejects("Float64", "0.0");
        rejects("Float64", "DEADBEEF"); // 8 nybbles is a Float32, not a Float64
        accepts("Float32", "DEADBEEF");
    }

    #[test]
    fn an_enum_label_is_rejected_where_its_id_is_accepted() {
        // The label is attacker-authored DDL and must never reach a comparison.
        let spec = "Enum8('ok' = 1, 'error' = -2)";
        accepts(spec, "1");
        accepts(spec, "-2");
        rejects(spec, "ok");
        rejects(spec, "error");
        rejects(spec, "0"); // non-contiguous ids: 0 is not in the set
        rejects(spec, "2");
    }

    #[test]
    fn enum8_ids_must_fit_an_int8_and_may_not_repeat() {
        assert!(parse_type("Enum8('a' = 128)").is_err());
        assert!(parse_type("Enum16('a' = 128)").is_ok());
        assert!(parse_type("Enum8('a' = 1, 'b' = 1)").is_err());
    }

    #[test]
    fn fixed_string_wants_exactly_two_nybbles_per_byte() {
        accepts("FixedString(2)", "00FF");
        rejects("FixedString(2)", "00F");
        rejects("FixedString(2)", "00FFA0");
        rejects("FixedString(2)", "00GG");
    }

    #[test]
    fn bool_is_zero_or_one_and_nothing_else() {
        accepts("Bool", "0");
        accepts("Bool", "1");
        rejects("Bool", "true");
        rejects("Bool", "2");
        rejects("Bool", "");
    }

    #[test]
    fn uuid_and_ip_addresses_must_be_canonical() {
        accepts("UUID", "123e4567-e89b-12d3-a456-426614174000");
        rejects("UUID", "123e4567e89b12d3a456426614174000");
        rejects("UUID", "{123e4567-e89b-12d3-a456-426614174000}");
        accepts("IPv4", "192.168.0.1");
        rejects("IPv4", "010.1.1.1"); // a leading zero means different things to different parsers
        rejects("IPv4", "999.1.1.1");
        accepts("IPv6", "::1");
        rejects("IPv6", "0:0:0:0:0:0:0:1"); // parses, but is not the canonical rendering
    }

    #[test]
    fn free_text_rejects_the_control_bytes_section_8_3_names() {
        accepts("String", "ordinary text");
        // Tab and newline reach here only as decoded canonical escapes, so they are content.
        accepts("String", "a\tb");
        accepts("String", "a\nb");
        for bad in [0x00u8, 0x01, 0x08, 0x0B, 0x0C, 0x0E, 0x1F] {
            let v = vec![b'a', bad, b'b'];
            let Err(e) = validator("String").check(&v) else {
                panic!("0x{bad:02x} should be rejected");
            };
            assert_eq!(e.exit_code(), ExitCode::Abort);
        }
    }

    #[test]
    fn free_text_must_be_utf8() {
        let Err(e) = validator("String").check(&[0xFF, 0xFE]) else {
            panic!("invalid UTF-8 should be rejected");
        };
        assert_eq!(e.exit_code(), ExitCode::Abort);
    }

    // -- composites ----------------------------------------------------------------------------

    #[test]
    fn array_of_float64_carries_hex_bit_strings_not_json_numbers() {
        let v = validator("Array(Float64)");
        v.check(br#"["4000000000000000","7FF0000000000000"]"#)
            .unwrap();
        // A JSON number is exactly the denormal trap the bit-string form exists to avoid.
        assert!(v.check(br#"[2.0]"#).is_err());
        assert!(v.check(br#"[null]"#).is_err());
        assert!(v.check(br#"{"a":1}"#).is_err());
    }

    #[test]
    fn array_elements_are_capped() {
        let t = parse_type("Array(UInt8)").unwrap();
        let r = rules_for(&t, 2).unwrap();
        r.columns[0].validator.check(b"[1,2]").unwrap();
        assert!(r.columns[0].validator.check(b"[1,2,3]").is_err());
    }

    #[test]
    fn a_tuple_flattens_to_one_column_per_element() {
        let r = rules("Tuple(UInt8, String)");
        assert_eq!(r.columns.len(), 2);
        assert_eq!(r.columns[0].suffix, ".1");
        assert_eq!(r.columns[1].suffix, ".2");
        assert!(!r.equal_length_group);
    }

    #[test]
    fn a_map_becomes_two_parallel_arrays_in_a_length_group() {
        let r = rules("Map(String, UInt32)");
        assert_eq!(r.columns.len(), 2);
        assert_eq!(r.columns[0].suffix, ".keys");
        assert_eq!(r.columns[1].suffix, ".values");
        assert!(r.equal_length_group, "Map must be an equal-length group");
    }

    #[test]
    fn map_sorts_pairs_rather_than_sorting_keys_alone() {
        // Sorting `mapKeys(c)` independently of `mapValues(c)` misaligns every row silently. Both
        // projections must sort the *zipped pairs* and differ only in which side they take.
        let col = Ident::new("m").unwrap();
        let r = rules("Map(String, UInt32)");
        let keys = r.columns[0].expr.render(&col);
        let values = r.columns[1].expr.render(&col);
        assert!(keys.contains("arrayZip"), "{keys}");
        assert!(values.contains("arrayZip"), "{values}");
        assert!(keys.contains("x.1"), "{keys}");
        assert!(values.contains("x.2"), "{values}");
    }

    #[test]
    fn nested_flattens_to_parallel_arrays_in_a_length_group() {
        let r = rules("Nested(a UInt8, b String)");
        assert_eq!(r.columns.len(), 2);
        assert_eq!(r.columns[0].suffix, ".a");
        assert_eq!(r.columns[1].suffix, ".b");
        assert!(r.equal_length_group);
    }

    #[test]
    fn low_cardinality_defers_entirely_to_its_inner_type() {
        assert_eq!(validator("LowCardinality(String)"), validator("String"));
        assert_eq!(validator("LowCardinality(UInt8)"), validator("UInt8"));
    }

    #[test]
    fn nullable_applies_the_inner_rule_and_changes_only_the_quarantine_type() {
        let plain = rules("String");
        let nullable = rules("Nullable(String)");
        assert_eq!(plain.quarantine, QuarantineType::String);
        assert_eq!(nullable.quarantine, QuarantineType::NullableString);
        assert!(!plain.nullable);
        assert!(nullable.nullable);
        assert_eq!(
            plain.columns[0].validator, nullable.columns[0].validator,
            "the non-null case is still the inner rule"
        );
    }

    #[test]
    fn nullable_may_not_wrap_a_composite_or_itself() {
        for spec in [
            "Nullable(Nullable(String))",
            "Nullable(Array(UInt8))",
            "Nullable(Map(String, UInt8))",
            "Nullable(Tuple(UInt8))",
        ] {
            let t = parse_type(spec).unwrap_or_else(|e| panic!("{spec} should parse: {e}"));
            assert!(
                rules_for(&t, DEFAULT_MAX_ARRAY_ELEMENTS).is_err(),
                "{spec} should have no rules"
            );
        }
    }

    #[test]
    fn array_of_nullable_and_low_cardinality_nullable_are_supported() {
        // Section 12 item 1 names both explicitly, so the matrix must carry them.
        rules("Array(Nullable(UInt8))");
        rules("LowCardinality(Nullable(String))");
    }

    // -- export expressions --------------------------------------------------------------------

    #[test]
    fn every_export_expression_quotes_its_identifier_exactly_once() {
        let col = Ident::new("value").unwrap();
        for spec in [
            "UInt8",
            "Float64",
            "Date",
            "DateTime",
            "DateTime64(3)",
            "FixedString(4)",
            "Bool",
            "String",
            "UUID",
            "Enum8('a' = 1)",
            "Array(UInt8)",
        ] {
            let r = rules(spec);
            for c in &r.columns {
                let sql = c.expr.render(&col);
                assert!(sql.contains("`value`"), "{spec}: {sql}");
                assert!(!sql.contains("``"), "{spec}: {sql}");
            }
        }
    }

    #[test]
    fn floats_export_as_their_reinterpreted_bit_pattern() {
        let col = Ident::new("f").unwrap();
        assert_eq!(
            rules("Float64").columns[0].expr.render(&col),
            "hex(reinterpretAsUInt64(`f`))"
        );
        assert_eq!(
            rules("Float32").columns[0].expr.render(&col),
            "hex(reinterpretAsUInt32(`f`))"
        );
    }

    #[test]
    fn enums_export_the_id_and_never_the_label() {
        let col = Ident::new("e").unwrap();
        let sql = rules("Enum8('ok' = 1)").columns[0].expr.render(&col);
        assert_eq!(sql, "CAST(`e` AS Int16)");
        assert!(!sql.contains("ok"), "the label must not reach SQL: {sql}");
    }

    #[test]
    fn an_identifier_outside_the_permitted_charset_is_refused() {
        for bad in ["", "a b", "a`b", "a;b", "a-b", "a.b", &"x".repeat(65)] {
            assert!(Ident::new(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(Ident::new("a_B9").is_ok());
        assert!(Ident::new(&"x".repeat(64)).is_ok());
    }

    // -- serialization -------------------------------------------------------------------------

    #[test]
    fn type_rules_serialize_to_a_reviewable_shape() {
        // The golden: `plan.json` embeds this verbatim, and the point of the whole step is that
        // the exact bound for a column is legible on a page before anything touches the cluster.
        let r = rules("Nullable(String)");
        let json = serde_json::to_string_pretty(&r).unwrap();
        let expected = r#"{
  "canonical": "Nullable(String)",
  "nullable": true,
  "quarantine": "NullableString",
  "equal_length_group": false,
  "columns": [
    {
      "suffix": "",
      "expr": "Identity",
      "validator": {
        "FreeText": {
          "max_len": null
        }
      }
    }
  ]
}"#;
        assert_eq!(json, expected);
    }

    // -- the pinned fixture --------------------------------------------------------------------

    /// Lift the type strings out of a pinned `CREATE TABLE` by line scan.
    ///
    /// Deliberately crude, and deliberately temporary: the restricted DDL parser is step 4, and it
    /// replaces this with the real thing while taking the same fixture unchanged. What this proves
    /// today is the check that matters now -- **the matrix has no type the table does not model.**
    fn types_declared_in(ddl: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for line in ddl.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix('`') else {
                continue;
            };
            let Some((name, tail)) = rest.split_once('`') else {
                continue;
            };
            let ty = tail.trim().trim_end_matches(',').trim();
            if !ty.is_empty() {
                out.push((name.to_owned(), ty.to_owned()));
            }
        }
        out
    }

    #[test]
    fn every_type_in_the_pinned_fixture_parses_and_has_rules() {
        let ddl = include_str!("../../ddl/typematrix.typematrix.sql");
        let declared = types_declared_in(ddl);
        assert!(
            declared.len() > 40,
            "the line scan found only {} columns; the fixture or the scan is wrong",
            declared.len()
        );
        for (name, ty) in &declared {
            let parsed =
                parse_type(ty).unwrap_or_else(|e| panic!("column `{name}` type `{ty}`: {e}"));
            rules_for(&parsed, DEFAULT_MAX_ARRAY_ELEMENTS)
                .unwrap_or_else(|e| panic!("column `{name}` type `{ty}` has no rules: {e}"));
        }
    }

    #[test]
    fn the_fixture_covers_the_types_section_12_item_1_names() {
        // Item 1 is explicit about which shapes the rehearsal corpus must exercise, and two of them
        // are easy to leave out: `Array(Nullable(T))` and `LowCardinality(Nullable(String))`.
        let ddl = include_str!("../../ddl/typematrix.typematrix.sql");
        let declared: Vec<String> = types_declared_in(ddl).into_iter().map(|(_, t)| t).collect();
        for required in [
            "Nullable(String)",
            "LowCardinality(Nullable(String))",
            "Array(Nullable(UInt8))",
            "Array(Float64)",
            "DateTime64(0)",
            "DateTime64(9)",
            "FixedString(16)",
            "Decimal(76, 20)",
            "Int256",
            "UInt256",
            "Map(String, UInt32)",
        ] {
            assert!(
                declared.iter().any(|t| t == required),
                "the fixture is missing {required}"
            );
        }
        // A non-contiguous enum with a negative id, which is what catches an implementation that
        // assumes ids are a dense 0..n range.
        assert!(
            declared
                .iter()
                .any(|t| t.starts_with("Enum8(") && t.contains("-3")),
            "the fixture needs a non-contiguous enum with a negative id"
        );
    }

    #[test]
    fn type_rules_round_trip_through_json_for_every_supported_type() {
        // `ColumnPlan` in `models.rs` embeds `TypeRules` and is `Deserialize`, so the rules have to
        // survive the trip. The 256-bit bounds are the interesting case: they travel as decimal
        // strings because a JSON number would silently truncate them.
        for spec in [
            "UInt8",
            "UInt256",
            "Int256",
            "Float64",
            "Decimal(76, 20)",
            "Bool",
            "String",
            "FixedString(16)",
            "Date",
            "Date32",
            "DateTime",
            "DateTime64(0)",
            "DateTime64(9)",
            "UUID",
            "IPv4",
            "IPv6",
            "Enum8('a' = 1, 'b' = -3)",
            "Nullable(String)",
            "LowCardinality(Nullable(String))",
            "Array(Nullable(UInt8))",
            "Array(Float64)",
            "Map(String, UInt32)",
            "Tuple(UInt8, String)",
            "Nested(a UInt8, b String)",
        ] {
            let original = rules(spec);
            let json = serde_json::to_string(&original).unwrap();
            let back: TypeRules = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("{spec} did not round-trip: {e}\n{json}"));
            assert_eq!(original, back, "{spec}");
        }
    }

    #[test]
    fn an_unknown_key_in_serialized_rules_is_a_hard_error() {
        // Same discipline as the pinned overrides: a key we do not recognise in a document that
        // decides what gets accepted is a hard error, not something to skip past.
        let json = r#"{"canonical":"UInt8","nullable":false,"quarantine":"String",
                       "equal_length_group":false,"columns":[],"tpyo":1}"#;
        assert!(serde_json::from_str::<TypeRules>(json).is_err());
    }

    #[test]
    fn a_range_bound_that_is_not_a_plain_decimal_integer_is_refused() {
        // The deserializer screens the shape before `num-bigint` sees it, for the same reason the
        // row path does: the parser tolerates `+` and `_` and would accept a bound we did not mean.
        for bad in [r#""1_000""#, r#""+1""#, r#""" "#, r#""1.5""#, "1000"] {
            let json = format!(r#"{{"min":{bad},"max":"10"}}"#);
            assert!(
                serde_json::from_str::<ValueRange>(&json).is_err(),
                "{bad} should be refused"
            );
        }
        assert!(serde_json::from_str::<ValueRange>(r#"{"min":"-5","max":"10"}"#).is_ok());
    }

    #[test]
    fn a_range_serializes_as_a_decimal_string_not_a_lossy_number() {
        // A UInt256 bound cannot survive a JSON number. If this ever regresses to `f64`, the
        // reviewable artifact silently stops being reviewable.
        let r = rules("UInt256");
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains(
                "\"115792089237316195423570985008687907853269984665640564039457584007913129639935\""
            ),
            "{json}"
        );
    }

    #[test]
    fn a_nested_field_projects_its_own_column_not_the_parent() {
        // ClickHouse stores a Nested as one parallel array per field. Rendering all three against
        // the parent produced two byte-identical expressions and read a column that is not
        // readable -- caught by eye in plan.json, which is what that document is for.
        let ty = parse_type("Nested(kind UInt8, at DateTime, note String)").unwrap();
        let rules = rules_for(&ty, DEFAULT_MAX_ARRAY_ELEMENTS).unwrap();
        let col = Ident::new("events").unwrap();
        let sql: Vec<String> = rules.columns.iter().map(|c| c.expr.render(&col)).collect();

        assert_eq!(sql.len(), 3);
        assert!(sql[0].contains("`events.kind`"), "{}", sql[0]);
        assert!(sql[1].contains("`events.at`"), "{}", sql[1]);
        assert!(sql[2].contains("`events.note`"), "{}", sql[2]);
        // No expression may address the parent, which is not a readable column.
        for e in &sql {
            assert!(!e.contains("`events`"), "addresses the parent: {e}");
        }
        // And every projection is distinct, which the bug made false for kind and note.
        let mut deduped = sql.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), sql.len(), "duplicate projections: {sql:?}");
    }

    #[test]
    fn an_identifier_cannot_be_deserialized_around_its_validator() {
        // `Ident` is rendered into SQL, so the charset check has to hold on every path a value can
        // arrive by -- including a hand-edited plan.json, not only `Ident::new`.
        assert!(serde_json::from_str::<Ident>(r#""events""#).is_ok());
        for hostile in [
            r#""a`, (SELECT 1) AS b, `c""#,
            r#""events.kind""#,
            r#""a b""#,
            r#""""#,
        ] {
            assert!(
                serde_json::from_str::<Ident>(hostile).is_err(),
                "{hostile} must not become an Ident"
            );
        }
    }
}

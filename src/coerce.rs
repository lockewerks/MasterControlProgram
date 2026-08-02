//! # Lenient Number Deserializers
//!
//! Some MCP clients stringify numeric inputs: the schema says "integer"
//! but the JSON body has `"1279"` instead of `1279`. That's cosmetically
//! wrong but semantically identical, and rejecting it just frustrates users
//! whose only crime is trusting their client's JSON encoder.
//!
//! These deserializers accept both JSON numbers and numeric strings, so
//! tool inputs like `{ "x": 610 }` and `{ "x": "610" }` both land on i32.
//!
//! Apply per-field via:
//!   #[serde(deserialize_with = "crate::coerce::num")]       for required
//!   #[serde(default, deserialize_with = "crate::coerce::opt_num")]  for Option

use serde::{Deserialize, Deserializer};
use std::fmt;
use std::str::FromStr;

fn kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Deserialize a required numeric field, accepting both JSON numbers and
/// numeric strings.
pub fn num<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + serde::de::DeserializeOwned,
    <T as FromStr>::Err: fmt::Display,
{
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Number(_) => {
            serde_json::from_value(v).map_err(serde::de::Error::custom)
        }
        serde_json::Value::String(s) => s.parse().map_err(serde::de::Error::custom),
        other => Err(serde::de::Error::custom(format!(
            "expected number or numeric string, got {}",
            kind(&other)
        ))),
    }
}

/// Deserialize an optional numeric field, accepting both JSON numbers and
/// numeric strings. Use with `#[serde(default, deserialize_with = "...")]`
/// so that missing fields still produce `None`.
pub fn opt_num<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + serde::de::DeserializeOwned,
    <T as FromStr>::Err: fmt::Display,
{
    let v = Option::<serde_json::Value>::deserialize(d)?;
    match v {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => {
            let parsed: T = serde_json::from_value(serde_json::Value::Number(n))
                .map_err(serde::de::Error::custom)?;
            Ok(Some(parsed))
        }
        Some(serde_json::Value::String(s)) => {
            Ok(Some(s.parse().map_err(serde::de::Error::custom)?))
        }
        Some(other) => Err(serde::de::Error::custom(format!(
            "expected number, numeric string, or null; got {}",
            kind(&other)
        ))),
    }
}

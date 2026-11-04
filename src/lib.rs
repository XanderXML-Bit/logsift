#![forbid(unsafe_code)]

//! Streaming tools for inspecting bunyan JSON logs.

pub mod input;
pub mod level;
pub mod normalize;
pub mod report;
pub mod time;

use ::time::OffsetDateTime;
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, Write};

use crate::level::Level;

/// A parsed bunyan line, retaining its exact input bytes for passthrough output.
#[derive(Debug)]
pub struct Record {
    /// Original input bytes, including a trailing newline when one was present.
    pub raw: Vec<u8>,
    /// The record's normalized severity.
    pub level: Level,
    /// The original message.
    pub msg: String,
    /// Parsed timestamp, when valid and present.
    pub timestamp: Option<OffsetDateTime>,
    fields: Value,
}

impl Record {
    /// Parses a single line as a bunyan record.
    pub fn parse(raw: Vec<u8>) -> Option<Self> {
        let text = std::str::from_utf8(&raw)
            .ok()?
            .trim_end_matches(['\r', '\n']);
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let fields: Value = serde_json::from_str(text).ok()?;
        let object = fields.as_object()?;
        let level = Level::from_json(object.get("level")?)?;
        let msg = object.get("msg")?.as_str()?.to_owned();
        let timestamp = object
            .get("time")
            .and_then(Value::as_str)
            .and_then(|value| crate::time::parse_timestamp(value).ok());
        Some(Self {
            raw,
            level,
            msg,
            timestamp,
            fields,
        })
    }

    /// Returns a field as its string value, or JSON text for non-string values.
    pub fn field(&self, key: &str) -> Option<String> {
        self.fields.get(key).map(json_value_string)
    }

    /// Returns the requested group, falling back to `name`.
    pub fn group(&self, field: &str) -> String {
        self.field(field)
            .or_else(|| self.field("name"))
            .unwrap_or_else(|| "<unknown>".to_owned())
    }
}

/// Converts a JSON value to the string form used by `--field` and grouping.
pub fn json_value_string(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

/// Writes bytes while treating a closed downstream pipe as successful completion.
pub fn write_output(mut writer: impl Write, bytes: &[u8]) -> Result<bool> {
    match writer.write_all(bytes).and_then(|()| writer.flush()) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Creates a fixed level-count map, including zero-count levels.
pub fn empty_level_counts() -> BTreeMap<String, u64> {
    Level::ALL
        .into_iter()
        .map(|level| (level.as_str().to_owned(), 0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::Record;

    #[test]
    fn invalid_or_missing_time_does_not_reject_anotherwise_valid_record() {
        assert!(Record::parse(br#"{"level":30,"msg":"ok"}"#.to_vec()).is_some());
        let invalid = Record::parse(br#"{"level":30,"msg":"ok","time":"later"}"#.to_vec()).unwrap();
        assert!(invalid.timestamp.is_none());
        assert!(Record::parse(br#"[]"#.to_vec()).is_none());
    }

    #[test]
    fn accepts_a_utf8_bom_without_changing_raw_bytes() {
        let raw = b"\xef\xbb\xbf{\"level\":30,\"msg\":\"ok\"}\n".to_vec();
        let record = Record::parse(raw.clone()).unwrap();
        assert_eq!(record.raw, raw);
    }
}

//! Bunyan severity parsing and comparison.

use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::Value;
use std::str::FromStr;

/// Bunyan's named severity levels.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Trace diagnostics.
    Trace = 10,
    /// Debug diagnostics.
    Debug = 20,
    /// Informational events.
    Info = 30,
    /// Warnings.
    Warn = 40,
    /// Errors.
    Error = 50,
    /// Fatal errors.
    Fatal = 60,
}

impl Level {
    /// Levels in ascending severity order.
    pub const ALL: [Self; 6] = [
        Self::Trace,
        Self::Debug,
        Self::Info,
        Self::Warn,
        Self::Error,
        Self::Fatal,
    ];

    /// Returns the canonical lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }

    /// Maps a numeric Bunyan level to the nearest named level not above it.
    pub const fn from_number(number: i64) -> Self {
        if number >= 60 {
            Self::Fatal
        } else if number >= 50 {
            Self::Error
        } else if number >= 40 {
            Self::Warn
        } else if number >= 30 {
            Self::Info
        } else if number >= 20 {
            Self::Debug
        } else {
            Self::Trace
        }
    }

    /// Reads a level from a JSON numeric value.
    pub fn from_json(value: &Value) -> Option<Self> {
        value.as_i64().map(Self::from_number)
    }
}

impl FromStr for Level {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            "fatal" => Ok(Self::Fatal),
            _ => match value.parse::<i64>() {
                Ok(number) => Ok(Self::from_number(number)),
                Err(_) => bail!("invalid level {value:?}; use a name or number"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Level;
    use std::str::FromStr;

    #[test]
    fn parses_names_and_numbers() {
        assert_eq!(Level::from_str("WARN").unwrap(), Level::Warn);
        assert_eq!(Level::from_str("35").unwrap(), Level::Info);
        assert_eq!(Level::from_str("-1").unwrap(), Level::Trace);
        assert_eq!(Level::from_str("99").unwrap(), Level::Fatal);
        assert!(Level::from_str("loud").is_err());
    }
}

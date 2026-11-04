//! Timestamp and compact duration parsing.

use anyhow::{Context, Result, bail};
use time::{Duration, OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

/// Largest accepted CLI duration in days.
pub const MAX_DURATION_DAYS: i64 = 36_500;
/// Largest accepted CLI duration in seconds.
pub const MAX_DURATION_SECONDS: i64 = MAX_DURATION_DAYS * 86_400;

/// Parses an RFC 3339 timestamp.
pub fn parse_timestamp(value: &str) -> Result<OffsetDateTime> {
    Ok(OffsetDateTime::parse(value, &Rfc3339)?)
}

/// Parses a positive duration from `30s`, `15m`, `2h`, or `1d`.
///
/// Durations are limited to [`MAX_DURATION_DAYS`] so relative bounds and burst
/// windows remain representable.
pub fn parse_duration(value: &str) -> Result<Duration> {
    let Some((unit_index, unit)) = value.char_indices().last() else {
        bail!("invalid duration {value:?}; use 30s, 15m, 2h, or 1d");
    };
    let number = &value[..unit_index];
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid duration {value:?}; use 30s, 15m, 2h, or 1d");
    }
    let number: u64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration {value:?}"))?;
    if number == 0 {
        bail!("duration must be positive");
    }
    let multiplier = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => bail!("invalid duration {value:?}; use s, m, h, or d"),
    };
    let seconds = number
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("duration is too large"))?;
    if seconds > MAX_DURATION_SECONDS as u64 {
        bail!("duration exceeds the maximum of {MAX_DURATION_DAYS}d");
    }
    Ok(Duration::seconds(seconds as i64))
}

/// Parses an absolute RFC 3339 timestamp or duration relative to `now`.
pub fn parse_time_bound(value: &str, now: OffsetDateTime) -> Result<OffsetDateTime> {
    match parse_timestamp(value) {
        Ok(timestamp) => Ok(timestamp),
        Err(_) => now
            .checked_sub(parse_duration(value)?)
            .ok_or_else(|| anyhow::anyhow!("relative time {value:?} is out of range")),
    }
}

/// Formats a timestamp in UTC for terminal and JSON reports.
pub fn format_timestamp(value: OffsetDateTime) -> Result<String> {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .context("format RFC 3339 timestamp")
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_DURATION_DAYS, format_timestamp, parse_duration, parse_time_bound, parse_timestamp,
    };
    use time::{Duration, macros::datetime};

    #[test]
    fn parses_durations_and_relative_bounds() {
        assert_eq!(parse_duration("15m").unwrap(), Duration::minutes(15));
        assert_eq!(
            parse_duration(&format!("{MAX_DURATION_DAYS}d")).unwrap(),
            Duration::days(MAX_DURATION_DAYS)
        );
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("3w").is_err());
        assert!(parse_duration("36501d").is_err());
        let now = datetime!(2026-01-01 00:00 UTC);
        assert_eq!(
            parse_time_bound("30s", now).unwrap(),
            now - Duration::seconds(30)
        );
        assert_eq!(parse_time_bound("2026-01-01T00:00:00Z", now).unwrap(), now);
        assert!(parse_timestamp("not-time").is_err());
    }

    #[test]
    fn rejects_unicode_suffixes_and_formats_utc() {
        assert!(parse_duration("5µ").is_err());
        assert!(parse_time_bound("é", datetime!(2026-01-01 00:00 UTC)).is_err());
        let offset = parse_timestamp("2026-01-01T05:00:00+05:00").unwrap();
        assert_eq!(format_timestamp(offset).unwrap(), "2026-01-01T00:00:00Z");
    }
}

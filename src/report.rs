//! Streaming aggregations and serializable report schemas.

use crate::{
    Record, empty_level_counts, level::Level, normalize::template, time::format_timestamp,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use time::OffsetDateTime;

/// Maximum distinct group names before later groups fold into `<other>`.
pub const MAX_GROUPS: usize = 10_000;
/// Maximum named templates in a summary or one burst window.
pub const MAX_TEMPLATES_PER_BUCKET: usize = 10_000;
/// Maximum timestamp minutes stored by one summary.
pub const MAX_SUMMARY_MINUTES: usize = 100_000;
/// Maximum windows stored by one burst accumulator.
pub const MAX_BURST_WINDOWS: usize = 100_000;
/// Maximum template entries across every burst window.
pub const MAX_BURST_TEMPLATE_ENTRIES: usize = 100_000;
/// Maximum bytes kept for a stored template string.
pub const MAX_TEMPLATE_BYTES: usize = 512;
/// Maximum bytes kept for a stored example message.
pub const MAX_EXAMPLE_BYTES: usize = 512;
/// Maximum bytes kept for a stored group name.
pub const MAX_GROUP_BYTES: usize = 512;

const OTHER: &str = "<other>";

/// A normalized message template in a report.
#[derive(Clone, Debug, Serialize)]
pub struct TemplateReport {
    /// Template after volatile values have been normalized.
    pub template: String,
    /// Number of matching records.
    pub count: u64,
    /// Highest severity seen for this template.
    pub highest_level: Level,
    /// First valid timestamp, if any.
    pub first_seen: Option<String>,
    /// Last valid timestamp, if any.
    pub last_seen: Option<String>,
    /// The first message, truncated to [`MAX_EXAMPLE_BYTES`] when needed.
    pub example: String,
}

#[derive(Clone, Debug)]
struct TemplateStats {
    count: u64,
    highest: Level,
    first: Option<OffsetDateTime>,
    last: Option<OffsetDateTime>,
    example: String,
}

impl TemplateStats {
    fn new(record: &Record) -> Self {
        Self {
            count: 0,
            highest: record.level,
            first: None,
            last: None,
            example: limit_text(&record.msg, MAX_EXAMPLE_BYTES),
        }
    }

    fn add(&mut self, record: &Record) -> Result<()> {
        increment(&mut self.count, "template record count")?;
        self.highest = self.highest.max(record.level);
        if let Some(timestamp) = record.timestamp {
            self.first = Some(self.first.map_or(timestamp, |old| old.min(timestamp)));
            self.last = Some(self.last.map_or(timestamp, |old| old.max(timestamp)));
        }
        Ok(())
    }

    fn report(&self, template: String) -> Result<TemplateReport> {
        Ok(TemplateReport {
            template,
            count: self.count,
            highest_level: self.highest,
            first_seen: self.first.map(format_timestamp).transpose()?,
            last_seen: self.last.map(format_timestamp).transpose()?,
            example: self.example.clone(),
        })
    }
}

/// The JSON schema emitted by `logsift summary --format json`.
#[derive(Debug, Serialize)]
pub struct SummaryReport {
    /// Valid bunyan records parsed from input.
    pub total_records: u64,
    /// Lines that were not usable bunyan records.
    pub unparsed_lines: u64,
    /// Earliest valid timestamp.
    pub first_timestamp: Option<String>,
    /// Latest valid timestamp.
    pub last_timestamp: Option<String>,
    /// Counts by canonical severity name.
    pub levels: BTreeMap<String, u64>,
    /// Counts by configured group value.
    pub groups: BTreeMap<String, u64>,
    /// Most frequent normalized messages.
    pub top_templates: Vec<TemplateReport>,
    /// Busiest warn-or-above minute, when timestamped records exist.
    pub busiest_warn_minute: Option<BusyMinute>,
}

/// One busiest warning-minute result.
#[derive(Debug, Serialize)]
pub struct BusyMinute {
    /// Window start in UTC.
    pub start: String,
    /// Number of warn-or-above records.
    pub count: u64,
}

/// Fixed-window burst result.
#[derive(Debug, Serialize)]
pub struct BurstReport {
    /// Aligned UTC window start.
    pub start: String,
    /// Aligned UTC window end.
    pub end: String,
    /// Matching record count.
    pub count: u64,
    /// The three most frequent templates.
    pub top_templates: Vec<TemplateReport>,
}

/// Bounded summary accumulator.
///
/// A summary stores at most [`MAX_GROUPS`] named groups plus `<other>`,
/// [`MAX_TEMPLATES_PER_BUCKET`] named templates plus `<other>`, and
/// [`MAX_SUMMARY_MINUTES`] warning-minute buckets.
pub struct Summary {
    group_by: String,
    template_cap: usize,
    total: u64,
    unparsed: u64,
    levels: BTreeMap<String, u64>,
    groups: BTreeMap<String, u64>,
    templates: HashMap<String, TemplateStats>,
    first: Option<OffsetDateTime>,
    last: Option<OffsetDateTime>,
    warn_minutes: BTreeMap<i64, u64>,
}

impl Summary {
    /// Creates a summary with a validated named-template cap.
    pub fn new(group_by: String, template_cap: usize) -> Result<Self> {
        validate_template_cap(template_cap)?;
        Ok(Self {
            group_by,
            template_cap,
            total: 0,
            unparsed: 0,
            levels: empty_level_counts(),
            groups: BTreeMap::new(),
            templates: HashMap::new(),
            first: None,
            last: None,
            warn_minutes: BTreeMap::new(),
        })
    }

    /// Counts a malformed, incomplete, or oversized input line.
    pub fn unparsed(&mut self) -> Result<()> {
        increment(&mut self.unparsed, "unparsed line count")
    }

    /// Adds one parsed record.
    pub fn add(&mut self, record: &Record) -> Result<()> {
        increment(&mut self.total, "record count")?;
        increment(
            self.levels
                .entry(record.level.as_str().to_owned())
                .or_default(),
            "level count",
        )?;

        let group = limit_text(&record.group(&self.group_by), MAX_GROUP_BYTES);
        let group_key = folded_group_key(&self.groups, &group);
        increment(self.groups.entry(group_key).or_default(), "group count")?;

        if let Some(timestamp) = record.timestamp {
            self.first = Some(self.first.map_or(timestamp, |old| old.min(timestamp)));
            self.last = Some(self.last.map_or(timestamp, |old| old.max(timestamp)));
            if record.level >= Level::Warn {
                let minute = bucket(timestamp, 60)?;
                if !self.warn_minutes.contains_key(&minute)
                    && self.warn_minutes.len() >= MAX_SUMMARY_MINUTES
                {
                    bail!(
                        "resource limit: summary reached {MAX_SUMMARY_MINUTES} distinct warning minutes"
                    );
                }
                increment(
                    self.warn_minutes.entry(minute).or_default(),
                    "warning-minute count",
                )?;
            }
        }

        let normalized = limit_text(&template(&record.msg), MAX_TEMPLATE_BYTES);
        let key = folded_template_key(&self.templates, &normalized, self.template_cap);
        self.templates
            .entry(key)
            .or_insert_with(|| TemplateStats::new(record))
            .add(record)
    }

    /// Finalizes the serializable report, retaining the requested templates.
    pub fn finish(self, top: usize) -> Result<SummaryReport> {
        let mut top_templates = reports(&self.templates)?;
        top_templates.truncate(top);
        let busiest_warn_minute = self
            .warn_minutes
            .into_iter()
            .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
            .map(|(start, count)| -> Result<BusyMinute> {
                Ok(BusyMinute {
                    start: format_timestamp(epoch(start)?)?,
                    count,
                })
            })
            .transpose()?;
        Ok(SummaryReport {
            total_records: self.total,
            unparsed_lines: self.unparsed,
            first_timestamp: self.first.map(format_timestamp).transpose()?,
            last_timestamp: self.last.map(format_timestamp).transpose()?,
            levels: self.levels,
            groups: self.groups,
            top_templates,
            busiest_warn_minute,
        })
    }
}

#[derive(Default)]
struct BurstStats {
    count: u64,
    templates: HashMap<String, TemplateStats>,
}

/// Bounded fixed-window burst accumulator.
///
/// The accumulator stores at most [`MAX_BURST_WINDOWS`] windows, each with at
/// most [`MAX_TEMPLATES_PER_BUCKET`] named templates plus `<other>`. It also
/// rejects input once all windows together reach
/// [`MAX_BURST_TEMPLATE_ENTRIES`] template entries.
pub struct Bursts {
    minimum: Level,
    seconds: i64,
    template_cap: usize,
    windows: BTreeMap<i64, BurstStats>,
    template_entries: usize,
}

impl Bursts {
    /// Creates a validated UTC-epoch-aligned burst accumulator.
    pub fn new(minimum: Level, seconds: i64, template_cap: usize) -> Result<Self> {
        if seconds <= 0 {
            bail!("burst window must be positive");
        }
        if seconds > crate::time::MAX_DURATION_SECONDS {
            bail!(
                "burst window exceeds the maximum of {}d",
                crate::time::MAX_DURATION_DAYS
            );
        }
        validate_template_cap(template_cap)?;
        Ok(Self {
            minimum,
            seconds,
            template_cap,
            windows: BTreeMap::new(),
            template_entries: 0,
        })
    }

    /// Adds a timestamped record at or above the configured severity.
    pub fn add(&mut self, record: &Record) -> Result<()> {
        if record.level < self.minimum {
            return Ok(());
        }
        let Some(timestamp) = record.timestamp else {
            return Ok(());
        };
        let window = burst_bucket(timestamp, self.seconds)?;
        let normalized = limit_text(&template(&record.msg), MAX_TEMPLATE_BYTES);
        let existing = self.windows.get(&window);
        let key = existing.map_or_else(
            || normalized.clone(),
            |stats| folded_template_key(&stats.templates, &normalized, self.template_cap),
        );
        let new_window = existing.is_none();
        let new_template = existing.is_none_or(|stats| !stats.templates.contains_key(&key));

        if new_window && self.windows.len() >= MAX_BURST_WINDOWS {
            bail!("resource limit: burst analysis reached {MAX_BURST_WINDOWS} windows");
        }
        if new_template && self.template_entries >= MAX_BURST_TEMPLATE_ENTRIES {
            bail!(
                "resource limit: burst analysis reached {MAX_BURST_TEMPLATE_ENTRIES} template entries"
            );
        }

        let stats = self.windows.entry(window).or_default();
        increment(&mut stats.count, "burst record count")?;
        if new_template {
            self.template_entries += 1;
        }
        stats
            .templates
            .entry(key)
            .or_insert_with(|| TemplateStats::new(record))
            .add(record)
    }

    /// Returns qualifying windows in chronological order.
    pub fn finish(self, threshold: u64) -> Result<Vec<BurstReport>> {
        self.windows
            .into_iter()
            .filter_map(|(start, stats)| (stats.count >= threshold).then_some((start, stats)))
            .map(|(start, stats)| {
                Ok(BurstReport {
                    start: format_timestamp(epoch(start)?)?,
                    end: format_timestamp(epoch(
                        start
                            .checked_add(self.seconds)
                            .context("burst window end is outside the supported range")?,
                    )?)?,
                    count: stats.count,
                    top_templates: reports(&stats.templates)?.into_iter().take(3).collect(),
                })
            })
            .collect()
    }
}

fn validate_template_cap(cap: usize) -> Result<()> {
    if cap == 0 || cap > MAX_TEMPLATES_PER_BUCKET {
        bail!("template cap must be between 1 and {MAX_TEMPLATES_PER_BUCKET}, inclusive");
    }
    Ok(())
}

fn folded_group_key(values: &BTreeMap<String, u64>, candidate: &str) -> String {
    if values.contains_key(candidate) || values.len() < MAX_GROUPS {
        candidate.to_owned()
    } else {
        OTHER.to_owned()
    }
}

fn folded_template_key(
    values: &HashMap<String, TemplateStats>,
    candidate: &str,
    cap: usize,
) -> String {
    if values.contains_key(candidate) || values.len() < cap {
        candidate.to_owned()
    } else {
        OTHER.to_owned()
    }
}

fn reports(values: &HashMap<String, TemplateStats>) -> Result<Vec<TemplateReport>> {
    let mut reports: Vec<_> = values
        .iter()
        .map(|(template, stats)| stats.report(template.clone()))
        .collect::<Result<_>>()?;
    reports.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.template.cmp(&right.template))
    });
    Ok(reports)
}

fn increment(value: &mut u64, label: &str) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("{label} exceeded u64::MAX"))?;
    Ok(())
}

fn bucket(timestamp: OffsetDateTime, seconds: i64) -> Result<i64> {
    if seconds <= 0 {
        bail!("time bucket must be positive");
    }
    timestamp
        .unix_timestamp()
        .div_euclid(seconds)
        .checked_mul(seconds)
        .context("time bucket is outside the supported range")
}

fn burst_bucket(timestamp: OffsetDateTime, seconds: i64) -> Result<i64> {
    let start = bucket(timestamp, seconds)?;
    let end = start
        .checked_add(seconds)
        .context("burst window end is outside the supported range")?;
    epoch(start)?;
    epoch(end)?;
    Ok(start)
}

fn epoch(seconds: i64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|error| anyhow::anyhow!(error))
        .context("bucket timestamp is outside the RFC 3339 range")
}

fn limit_text(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let marker = "…";
    let mut end = limit.saturating_sub(marker.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{marker}", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::{
        Bursts, MAX_BURST_TEMPLATE_ENTRIES, MAX_BURST_WINDOWS, MAX_EXAMPLE_BYTES, MAX_GROUPS,
        MAX_SUMMARY_MINUTES, MAX_TEMPLATE_BYTES, MAX_TEMPLATES_PER_BUCKET, Summary,
    };
    use crate::{Record, level::Level};

    fn record(message: &str, group: &str, timestamp: &str) -> Record {
        Record::parse(
            format!(
                r#"{{"level":50,"msg":{message:?},"component":{group:?},"time":"{timestamp}"}}"#
            )
            .into_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn folds_groups_after_the_group_limit() {
        let mut summary = Summary::new("component".into(), MAX_TEMPLATES_PER_BUCKET).unwrap();
        for number in 0..=MAX_GROUPS {
            summary
                .add(&record(
                    "same",
                    &format!("group-{number}"),
                    "2026-01-01T00:00:00Z",
                ))
                .unwrap();
        }
        let report = summary.finish(0).unwrap();
        assert_eq!(report.groups.len(), MAX_GROUPS + 1);
        assert_eq!(report.groups.get("<other>"), Some(&1));
    }

    #[test]
    fn rejects_invalid_burst_windows_and_global_template_overflow() {
        assert!(Bursts::new(Level::Warn, 0, MAX_TEMPLATES_PER_BUCKET).is_err());
        let mut bursts = Bursts::new(Level::Warn, 60, MAX_TEMPLATES_PER_BUCKET).unwrap();
        bursts.template_entries = MAX_BURST_TEMPLATE_ENTRIES;
        let error = bursts
            .add(&record("new template", "api", "2026-01-01T00:00:00Z"))
            .unwrap_err();
        assert!(error.to_string().contains("resource limit"));
    }

    #[test]
    fn reports_unrepresentable_burst_ends_instead_of_using_epoch() {
        let mut bursts = Bursts::new(Level::Warn, 1, MAX_TEMPLATES_PER_BUCKET).unwrap();
        let error = bursts
            .add(&record("edge", "api", "9999-12-31T23:59:59Z"))
            .unwrap_err();
        assert!(error.to_string().contains("RFC 3339 range"));
    }

    #[test]
    fn rejects_excess_burst_windows() {
        let mut bursts = Bursts::new(Level::Warn, 60, MAX_TEMPLATES_PER_BUCKET).unwrap();
        for window in 0..MAX_BURST_WINDOWS as i64 {
            bursts.windows.insert(window * 60, Default::default());
        }
        let error = bursts
            .add(&record("new window", "api", "2026-01-01T00:00:00Z"))
            .unwrap_err();
        assert!(error.to_string().contains("resource limit"));
    }

    #[test]
    fn rejects_excess_summary_minutes() {
        let mut summary = Summary::new("component".into(), MAX_TEMPLATES_PER_BUCKET).unwrap();
        for minute in 0..MAX_SUMMARY_MINUTES as i64 {
            summary.warn_minutes.insert(minute * 60, 1);
        }
        let error = summary
            .add(&record("x", "api", "2026-01-01T00:00:00Z"))
            .unwrap_err();
        assert!(error.to_string().contains("resource limit"));
    }

    #[test]
    fn bounds_template_and_example_text_on_utf8_boundaries() {
        let message = "é".repeat(MAX_TEMPLATE_BYTES);
        let mut summary = Summary::new("component".into(), MAX_TEMPLATES_PER_BUCKET).unwrap();
        summary
            .add(&record(&message, "api", "2026-01-01T00:00:00Z"))
            .unwrap();
        let report = summary.finish(1).unwrap();
        let item = &report.top_templates[0];
        assert!(item.template.len() <= MAX_TEMPLATE_BYTES);
        assert!(item.example.len() <= MAX_EXAMPLE_BYTES);
        assert!(item.template.ends_with('…'));
        assert!(item.example.ends_with('…'));
    }
}

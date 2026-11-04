use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use logsift::{
    Record,
    input::{self, InputLine, LineControl},
    level::Level,
    report::{Bursts, MAX_TEMPLATES_PER_BUCKET, Summary},
    time::{parse_duration, parse_time_bound},
    write_output,
};
use serde_json::json;
use std::{
    io::{self},
    path::PathBuf,
    process::ExitCode,
};
use time::OffsetDateTime;

#[derive(Parser)]
#[command(name = "logsift", version, about = "Triage bunyan-format JSON logs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Summarize levels, groups, templates, and warning activity.
    Summary(SummaryArgs),
    /// Print original log lines matching every requested filter.
    Filter(FilterArgs),
    /// Find dense windows of warning or error activity.
    Bursts(BurstArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Args)]
struct Shared {
    /// Output style. Filter deliberately accepts text only.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Exit 2 when an eligible record meets or exceeds this severity.
    #[arg(long)]
    fail_on: Option<Level>,
    /// Files, directories, or `-` for stdin; no paths reads stdin.
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
}

#[derive(Args)]
struct SummaryArgs {
    #[command(flatten)]
    shared: Shared,
    /// Field used for group counts, with `name` fallback.
    #[arg(long, default_value = "component")]
    group_by: String,
    /// Number of message templates to show.
    #[arg(long, default_value_t = 10)]
    top: usize,
}

#[derive(Args)]
struct FilterArgs {
    #[command(flatten)]
    shared: Shared,
    /// Minimum severity, by name or numeric Bunyan level.
    #[arg(long)]
    level: Option<Level>,
    /// Include timestamps at or after this RFC 3339 or relative time.
    #[arg(long)]
    since: Option<String>,
    /// Include timestamps at or before this RFC 3339 or relative time.
    #[arg(long)]
    until: Option<String>,
    /// Group field used by `--group`.
    #[arg(long, default_value = "component")]
    group_by: String,
    /// Required group value.
    #[arg(long)]
    group: Option<String>,
    /// Required JSON field equality, in KEY=VALUE form; repeatable.
    #[arg(long = "field")]
    fields: Vec<String>,
    /// Required substring in `msg`.
    #[arg(long)]
    grep: Option<String>,
    /// Make `--grep` case-insensitive.
    #[arg(short = 'i', requires = "grep")]
    insensitive: bool,
}

#[derive(Args)]
struct BurstArgs {
    #[command(flatten)]
    shared: Shared,
    /// Minimum severity included in a window.
    #[arg(long, default_value = "warn")]
    level: Level,
    /// Fixed UTC-epoch-aligned window duration.
    #[arg(long, default_value = "1m")]
    window: String,
    /// Minimum matching records in a window.
    #[arg(long, default_value_t = 10)]
    threshold: u64,
}

struct Run {
    failed: bool,
    broken_pipe: bool,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let status = if error.use_stderr() { 1 } else { 0 };
            let _ = error.print();
            return ExitCode::from(status);
        }
    };
    match run(cli) {
        Ok(result) if result.failed => ExitCode::from(2),
        Ok(result) if result.broken_pipe => ExitCode::SUCCESS,
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("logsift: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<Run> {
    match cli.command {
        Command::Summary(args) => summary(args),
        Command::Filter(args) => filter(args),
        Command::Bursts(args) => bursts(args),
    }
}

fn summary(args: SummaryArgs) -> Result<Run> {
    let mut summary = Summary::new(args.group_by, MAX_TEMPLATES_PER_BUCKET)?;
    let mut failed = false;
    input::for_each_line(&args.shared.paths, |line| {
        match line {
            InputLine::Bytes(raw) => {
                if let Some(record) = Record::parse(raw) {
                    failed |= args
                        .shared
                        .fail_on
                        .is_some_and(|level| record.level >= level);
                    summary.add(&record)?;
                } else {
                    summary.unparsed()?;
                }
            }
            InputLine::Oversized => summary.unparsed()?,
        }
        Ok(LineControl::Continue)
    })?;
    let report = summary.finish(args.top)?;
    let output = match args.shared.format {
        Format::Json => json_output(&report)?,
        Format::Text => summary_text(&report).into_bytes(),
    };
    let broken_pipe = !write_output(io::stdout().lock(), &output)?;
    Ok(Run {
        failed,
        broken_pipe,
    })
}

fn filter(args: FilterArgs) -> Result<Run> {
    if matches!(args.shared.format, Format::Json) {
        anyhow::bail!(
            "--format json is not supported by filter; filter preserves original text lines"
        );
    }
    let now = OffsetDateTime::now_utc();
    let since = args
        .since
        .as_deref()
        .map(|value| parse_time_bound(value, now))
        .transpose()
        .context("parse --since")?;
    let until = args
        .until
        .as_deref()
        .map(|value| parse_time_bound(value, now))
        .transpose()
        .context("parse --until")?;
    let fields = args
        .fields
        .iter()
        .map(|value| split_field(value))
        .collect::<Result<Vec<_>>>()?;
    let mut failed = false;
    let mut broken_pipe = false;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    input::for_each_line(&args.shared.paths, |line| {
        if let InputLine::Bytes(raw) = line {
            let Some(record) = Record::parse(raw) else {
                return Ok(LineControl::Continue);
            };
            if matches_filter(&record, &args, since, until, &fields) {
                failed |= args
                    .shared
                    .fail_on
                    .is_some_and(|level| record.level >= level);
                if !write_output(&mut stdout, &record.raw)? {
                    broken_pipe = true;
                    return Ok(LineControl::Stop);
                }
            }
        }
        Ok(LineControl::Continue)
    })?;
    Ok(Run {
        failed,
        broken_pipe,
    })
}

fn bursts(args: BurstArgs) -> Result<Run> {
    let seconds = parse_duration(&args.window)
        .context("parse --window")?
        .whole_seconds();
    let mut bursts = Bursts::new(args.level, seconds, MAX_TEMPLATES_PER_BUCKET)?;
    let mut failed = false;
    input::for_each_line(&args.shared.paths, |line| {
        if let InputLine::Bytes(raw) = line {
            if let Some(record) = Record::parse(raw) {
                let eligible = record.timestamp.is_some() && record.level >= args.level;
                failed |= eligible
                    && args
                        .shared
                        .fail_on
                        .is_some_and(|level| record.level >= level);
                bursts.add(&record)?;
            }
        }
        Ok(LineControl::Continue)
    })?;
    let report = bursts.finish(args.threshold)?;
    let output = match args.shared.format {
        Format::Json => json_output(&json!({ "bursts": report }))?,
        Format::Text => bursts_text(&report).into_bytes(),
    };
    let broken_pipe = !write_output(io::stdout().lock(), &output)?;
    Ok(Run {
        failed,
        broken_pipe,
    })
}

fn split_field(value: &str) -> Result<(String, String)> {
    let (key, expected) = value.split_once('=').context("--field must be KEY=VALUE")?;
    if key.is_empty() {
        anyhow::bail!("--field key must not be empty");
    }
    Ok((key.to_owned(), expected.to_owned()))
}

fn json_output(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    let mut output = serde_json::to_vec_pretty(value)?;
    output.push(b'\n');
    Ok(output)
}

fn matches_filter(
    record: &Record,
    args: &FilterArgs,
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
    fields: &[(String, String)],
) -> bool {
    if args.level.is_some_and(|level| record.level < level) {
        return false;
    }
    if since.is_some() || until.is_some() {
        let Some(timestamp) = record.timestamp else {
            return false;
        };
        if since.is_some_and(|bound| timestamp < bound)
            || until.is_some_and(|bound| timestamp > bound)
        {
            return false;
        }
    }
    if args
        .group
        .as_ref()
        .is_some_and(|group| record.group(&args.group_by) != *group)
    {
        return false;
    }
    if fields
        .iter()
        .any(|(key, expected)| record.field(key).as_deref() != Some(expected))
    {
        return false;
    }
    if let Some(needle) = &args.grep {
        if args.insensitive {
            if !record.msg.to_lowercase().contains(&needle.to_lowercase()) {
                return false;
            }
        } else if !record.msg.contains(needle) {
            return false;
        }
    }
    true
}

fn summary_text(report: &logsift::report::SummaryReport) -> String {
    let mut output = format!(
        "Records: {}  Unparsed: {}\nTime range: {} .. {}\n\nLevels\n",
        report.total_records,
        report.unparsed_lines,
        report.first_timestamp.as_deref().unwrap_or("-"),
        report.last_timestamp.as_deref().unwrap_or("-")
    );
    for level in Level::ALL {
        let count = report
            .levels
            .get(level.as_str())
            .copied()
            .unwrap_or_default();
        output.push_str(&format!("  {:<5} {count:>8}\n", level.as_str()));
    }
    output.push_str("\nGroups\n");
    for (group, count) in &report.groups {
        output.push_str(&format!("  {:<24} {count:>8}\n", escape_text(group)));
    }
    output.push_str("\nTop templates\n");
    for item in &report.top_templates {
        output.push_str(&format!(
            "  {count:>5} {level:<5} {template}\n        first: {first}  last: {last}\n        example: {example}\n",
            count = item.count,
            level = item.highest_level.as_str(),
            template = escape_text(&item.template),
            first = item.first_seen.as_deref().unwrap_or("-"),
            last = item.last_seen.as_deref().unwrap_or("-"),
            example = escape_text(&item.example),
        ));
    }
    output.push_str("\nBusiest warn-or-above minute\n");
    match &report.busiest_warn_minute {
        Some(item) => output.push_str(&format!("  {}  {}\n", item.start, item.count)),
        None => output.push_str("  -\n"),
    }
    output
}

fn bursts_text(reports: &[logsift::report::BurstReport]) -> String {
    let mut output = String::new();
    for report in reports {
        output.push_str(&format!(
            "{} .. {}  count: {}\n",
            report.start, report.end, report.count
        ));
        for item in &report.top_templates {
            output.push_str(&format!(
                "  {:>5} {}\n",
                item.count,
                escape_text(&item.template)
            ));
        }
    }
    if output.is_empty() {
        output.push_str("No bursts found.\n");
    }
    output
}

fn escape_text(value: &str) -> String {
    value.escape_debug().to_string()
}

#[cfg(test)]
mod tests {
    use super::{FilterArgs, Shared, matches_filter};
    use logsift::{Record, level::Level};
    use std::path::PathBuf;
    use time::macros::datetime;

    #[test]
    fn time_boundaries_are_inclusive() {
        let record =
            Record::parse(br#"{"level":40,"msg":"x","time":"2026-01-01T00:00:00Z"}"#.to_vec())
                .unwrap();
        let args = FilterArgs {
            shared: Shared {
                format: super::Format::Text,
                fail_on: None,
                paths: Vec::<PathBuf>::new(),
            },
            level: Some(Level::Warn),
            since: None,
            until: None,
            group_by: "component".into(),
            group: None,
            fields: vec![],
            grep: None,
            insensitive: false,
        };
        let at = datetime!(2026-01-01 00:00 UTC);
        assert!(matches_filter(&record, &args, Some(at), Some(at), &[]));
    }
}

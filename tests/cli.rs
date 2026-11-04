use assert_cmd::Command;
use flate2::{Compression, write::GzEncoder};
use logsift::input::MAX_LINE_BYTES;
use predicates::prelude::*;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command as ProcessCommand, ExitStatus, Stdio},
    thread,
    time::Duration,
};
use tempfile::tempdir;

fn fixture() -> &'static str {
    "tests/fixtures/app.log"
}

fn binary() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("logsift").into()
}

fn command() -> Command {
    Command::new(binary())
}

fn gzip_member(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn summary_reports_counts_and_json_schema() {
    let mut command = command();
    command.args(["summary", "--format", "json", fixture()]);
    command.assert().success().stdout(
        predicate::str::contains("\"total_records\": 14")
            .and(predicate::str::contains("\"unparsed_lines\": 2"))
            .and(predicate::str::contains("\"top_templates\"")),
    );
}

#[test]
fn filter_preserves_original_line_bytes() {
    let expected = fs::read_to_string(fixture())
        .unwrap()
        .lines()
        .find(|line| line.contains("job 105"))
        .unwrap()
        .to_owned()
        + "\n";
    let mut command = command();
    command.args(["filter", "--field", "job=105", fixture()]);
    command.assert().success().stdout(expected);
}

#[test]
fn filter_concatenates_unterminated_raw_records_across_files() {
    let directory = tempdir().unwrap();
    let first = directory.path().join("a.log");
    let second = directory.path().join("b.log");
    let first_bytes = br#"{"level":50,"msg":"first"}"#;
    let second_bytes = b"{\"level\":50,\"msg\":\"second\"}\n";
    fs::write(&first, first_bytes).unwrap();
    fs::write(&second, second_bytes).unwrap();

    let mut command = command();
    command.args([
        "filter",
        "--level",
        "error",
        first.to_str().unwrap(),
        second.to_str().unwrap(),
    ]);
    let expected = [first_bytes.as_slice(), second_bytes.as_slice()].concat();
    command.assert().success().stdout(expected);
}

#[test]
fn finds_burst_and_returns_fail_status() {
    let mut burst = command();
    burst.args(["bursts", "--threshold", "10", fixture()]);
    burst
        .assert()
        .success()
        .stdout(predicate::str::contains("count: 10"));

    let mut filter = command();
    filter.args([
        "filter",
        "--level",
        "error",
        "--fail-on",
        "error",
        fixture(),
    ]);
    filter.assert().code(2);

    let mut summary = command();
    summary.args(["summary", "--fail-on", "error", fixture()]);
    summary.assert().code(2);
}

#[test]
fn bursts_fail_on_eligible_records_even_below_the_render_threshold() {
    let directory = tempdir().unwrap();
    let log = directory.path().join("one-error.log");
    fs::write(
        &log,
        b"{\"level\":50,\"msg\":\"x\",\"time\":\"2026-01-01T00:00:00Z\"}\n",
    )
    .unwrap();
    let mut command = command();
    command.args([
        "bursts",
        "--threshold",
        "2",
        "--fail-on",
        "error",
        log.to_str().unwrap(),
    ]);
    command
        .assert()
        .code(2)
        .stdout(predicate::str::contains("No bursts found."));
}

#[test]
fn reads_multi_member_gzip_from_file_and_stdin() {
    let directory = tempdir().unwrap();
    let compressed = directory.path().join("not-an-extension");
    let first = b"{\"level\":30,\"msg\":\"first\"}\n";
    let second = b"{\"level\":50,\"msg\":\"second\"}\n";
    let bytes = [gzip_member(first), gzip_member(second)].concat();
    fs::write(&compressed, &bytes).unwrap();

    let mut summary = command();
    summary.args(["summary", "--format", "json", compressed.to_str().unwrap()]);
    summary
        .assert()
        .success()
        .stdout(predicate::str::contains("\"total_records\": 2"));

    let mut filter = command();
    filter.args(["filter", compressed.to_str().unwrap()]);
    filter
        .assert()
        .success()
        .stdout([first.as_slice(), second.as_slice()].concat());

    let mut child = ProcessCommand::new(binary())
        .args(["summary", "--format", "json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&bytes).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("\"total_records\": 2")
    );
}

#[test]
fn json_output_is_newline_terminated() {
    let mut command = command();
    command.args(["bursts", "--format", "json", "--threshold", "10", fixture()]);
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.ends_with(b"\n"));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("\"bursts\""));
    assert!(text.contains("\"top_templates\""));
}

#[test]
fn rejects_json_filter_format_and_survives_bad_lines() {
    let mut filter = command();
    filter.args(["filter", "--format", "json", fixture()]);
    filter
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not supported"));

    let mut summary = command();
    summary.args(["summary", fixture()]);
    summary
        .assert()
        .success()
        .stdout(predicate::str::contains("Unparsed: 2"));
}

#[test]
fn rejects_unicode_and_excessive_cli_durations_without_panicking() {
    for arguments in [
        vec!["filter", "--since", "5µ", fixture()],
        vec!["filter", "--since", "9999999d", fixture()],
        vec!["bursts", "--window", "100000000d", fixture()],
    ] {
        let mut command = command();
        command.args(arguments);
        command
            .assert()
            .code(1)
            .stderr(predicate::str::contains("panicked at").not());
    }
}

#[test]
fn counts_oversized_lines_as_unparsed_and_continues() {
    let directory = tempdir().unwrap();
    let log = directory.path().join("oversized.log");
    let mut bytes = b"{\"level\":30,\"msg\":\"before\"}\n".to_vec();
    bytes.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES + 1));
    bytes.extend_from_slice(b"\n{\"level\":30,\"msg\":\"after\"}\n");
    fs::write(&log, bytes).unwrap();

    let mut command = command();
    command.args(["summary", "--format", "json", log.to_str().unwrap()]);
    command.assert().success().stdout(
        predicate::str::contains("\"total_records\": 2")
            .and(predicate::str::contains("\"unparsed_lines\": 1")),
    );
}

#[test]
fn escapes_untrusted_control_characters_in_text_reports() {
    let directory = tempdir().unwrap();
    let log = directory.path().join("controls.log");
    fs::write(
        &log,
        b"{\"level\":50,\"component\":\"\\u001b[2Jgroup\",\"msg\":\"x\\nforged \\u001b[2J\",\"time\":\"2026-01-01T00:00:00Z\"}\n",
    )
    .unwrap();

    let mut summary = command();
    summary.args(["summary", log.to_str().unwrap()]);
    let summary = summary.output().unwrap();
    assert!(summary.status.success());
    let summary = String::from_utf8(summary.stdout).unwrap();
    assert!(!summary.contains('\u{1b}'));
    assert!(summary.contains("\\u{1b}"));
    assert!(summary.contains("x\\nforged"));

    let mut bursts = command();
    bursts.args(["bursts", "--threshold", "1", log.to_str().unwrap()]);
    let bursts = bursts.output().unwrap();
    assert!(bursts.status.success());
    let bursts = String::from_utf8(bursts.stdout).unwrap();
    assert!(!bursts.contains('\u{1b}'));
    assert!(bursts.contains("\\u{1b}"));
}

#[cfg(unix)]
#[test]
fn directory_walk_skips_symbolic_link_loops() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    let logs = directory.path().join("logs");
    fs::create_dir(&logs).unwrap();
    fs::write(logs.join("one.log"), b"{\"level\":30,\"msg\":\"x\"}\n").unwrap();
    symlink(".", logs.join("self")).unwrap();

    let mut command = command();
    command.args([
        "summary",
        "--format",
        "json",
        logs.to_str().unwrap(),
        logs.join("one.log").to_str().unwrap(),
    ]);
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("\"total_records\": 1"));
}

#[cfg(unix)]
#[test]
fn reads_an_explicit_named_pipe_without_seeking() {
    let directory = tempdir().unwrap();
    let pipe = directory.path().join("logs.pipe");
    let status = ProcessCommand::new("mkfifo").arg(&pipe).status().unwrap();
    assert!(status.success());

    let child = ProcessCommand::new(binary())
        .args(["summary", "--format", "json", pipe.to_str().unwrap()])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pipe_writer = pipe.clone();
    let writer = thread::spawn(move || {
        let mut pipe = fs::OpenOptions::new()
            .write(true)
            .open(pipe_writer)
            .unwrap();
        pipe.write_all(b"{\"level\":30,\"msg\":\"stream\"}\n")
            .unwrap();
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("\"total_records\": 1")
    );
}

fn output_pipe_status(fail_on: bool) -> ExitStatus {
    let mut process = ProcessCommand::new(binary());
    process.args(["filter", "--level", "error"]);
    if fail_on {
        process.args(["--fail-on", "error"]);
    }
    let mut child = process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let record = b"{\"level\":50,\"msg\":\"x\"}\n";
    stdin.write_all(record).unwrap();
    stdin.flush().unwrap();
    let mut first_line = Vec::new();
    stdout.read_until(b'\n', &mut first_line).unwrap();
    assert_eq!(first_line, record);
    drop(stdout);
    thread::sleep(Duration::from_millis(50));

    stdin.write_all(record).unwrap();
    stdin.flush().unwrap();
    wait_promptly(&mut child)
}

fn wait_promptly(child: &mut Child) -> ExitStatus {
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("logsift kept reading after its output pipe closed");
}

#[test]
fn stops_reading_promptly_when_the_output_pipe_closes() {
    assert!(output_pipe_status(false).success());
}

#[test]
fn fail_on_takes_precedence_over_a_later_broken_pipe() {
    assert_eq!(output_pipe_status(true).code(), Some(2));
}

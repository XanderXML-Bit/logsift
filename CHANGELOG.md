# Changelog

## Unreleased

- Skip symbolic links during directory walks and decode every gzip member.
- Bound input lines, groups, summary minutes, burst windows, and burst templates.
- Return errors for invalid durations, unrepresentable windows, and resource limits.
- Stop filtering after a broken pipe while preserving prior `--fail-on` status.
- Escape control characters in text reports and harden template normalization.
- Lock CI dependency resolution and run tests on the Rust 1.85 MSRV job.

## 0.1.0 - 2026-11-03

- Initial release with streaming bunyan summaries, passthrough filtering, and burst detection.
- Added transparent magic-byte gzip input, bounded message-template aggregation, JSON reports, tests, and CI.

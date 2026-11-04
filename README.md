# logsift

[![CI](https://github.com/XanderXML-Bit/logsift/actions/workflows/ci.yml/badge.svg)](https://github.com/XanderXML-Bit/logsift/actions/workflows/ci.yml)

`logsift` triages line-delimited bunyan JSON logs. It summarizes severity,
groups, and templates. It filters raw matching records. It also finds dense
warning and error windows.

## Why it exists

Bunyan-format JSON is a common structured log format for Rust services, for
example those built on `slog-bunyan`. During an incident, an operator often
has a large log file and three questions to answer:

- What is failing?
- Since when?
- Which component is involved?

`logsift` answers them in one streaming pass. It runs in bounded memory and
needs no index, daemon, or network access.

It is built to be safe on hostile input. Log content is treated as untrusted:

- Text reports escape terminal control sequences.
- Every accumulator has a documented cap.
- Oversized lines are skipped without buffering them.
- Directory walks do not follow symlinks.
- The template normalizer runs in linear time.

`--fail-on LEVEL` makes it usable as a CI or deploy gate.

## Install

Install the locked dependency set from the repository.

```sh
cargo install --locked --git https://github.com/XanderXML-Bit/logsift
```

Run a local checkout with the cached dependency set.

```sh
cargo run --offline --locked -- --help
```

Rust 1.85 or later is supported.

## Start quickly

```sh
logsift summary production.log.gz
logsift filter --level error --since 15m --group jobs production.log
logsift bursts --window 5m --threshold 20 logs/
```

Supply files, readable named streams, directories, or `-` for standard input.
With no paths, logsift reads standard input. Directory walks use sorted entries
and skip symbolic links. An explicit directory symlink is rejected. An explicit
non-directory symlink can be read.

Logsift detects gzip from its first two bytes. It replays those bytes before
reading records. It reads every member in a concatenated gzip stream. A
truncated gzip stream exits with status 1.

## Use commands

### `summary`

`summary` reports usable records, unparsed lines, time range, levels, groups,
templates, and the busiest warning-or-above minute. `--group-by FIELD` defaults
to `component` and falls back to `name`. `--top N` defaults to 10.

This is the actual output of the following command.

```sh
cargo run --offline --locked -- summary tests/fixtures/app.log
```

```text
Records: 14  Unparsed: 2
Time range: 2026-01-15T00:00:00Z .. 2026-01-15T00:02:00Z

Levels
  trace        0
  debug        1
  info         1
  warn         1
  error       10
  fatal        1

Groups
  api                             3
  jobs                           11

Top templates
     10 error job <n> failed on sled<n>
        first: 2026-01-15T00:01:01Z  last: 2026-01-15T00:01:10Z
        example: job 100 failed on sled7
      1 warn  connection from <ip> delayed
        first: 2026-01-15T00:00:50Z  last: 2026-01-15T00:00:50Z
        example: connection from 10.0.0.8:443 delayed
      1 debug listening on <ip>
        first: 2026-01-15T00:00:00Z  last: 2026-01-15T00:00:00Z
        example: listening on 127.0.0.1:8080
      1 info  request <n> completed in <n>
        first: 2026-01-15T00:00:10Z  last: 2026-01-15T00:00:10Z
        example: request 42 completed in 15ms
      1 fatal worker <uuid> stopped
        first: 2026-01-15T00:02:00Z  last: 2026-01-15T00:02:00Z
        example: worker 550e8400-e29b-41d4-a716-446655440000 stopped

Busiest warn-or-above minute
  2026-01-15T00:01:00Z  10
```

### `filter`

`filter` prints the original bytes for records that satisfy every filter. Use
`--level`, inclusive `--since` or `--until`, `--group`, repeatable `--field`,
and `--grep`. Add `-i` for case-insensitive matching.

Time bounds accept RFC 3339 timestamps or `30s`, `15m`, `2h`, and `1d` values.
They cannot exceed `36500d`. A record without a valid timestamp does not match
a time filter.

`filter` rejects `--format json`. Re-serializing would change its raw-byte
contract. It does not add a newline between records. Therefore, an unterminated
matching record immediately joins the next matching record, including across
file boundaries. This behavior preserves the input bytes exactly.

This is the actual output of the following command.

```sh
cargo run --offline --locked -- filter --group jobs --grep 'job 105' tests/fixtures/app.log
```

```json
{"v":0,"level":50,"name":"worker","hostname":"demo","pid":202,"time":"2026-01-15T00:01:06Z","msg":"job 105 failed on sled7","component":"jobs","job":"105"}
```

### `bursts`

`bursts` finds fixed UTC-epoch-aligned windows at or above `--level`. The
default level is `warn`. The default window is `1m`. The default threshold is
10. Each result includes its three most frequent templates.

This is the actual output of the following command.

```sh
cargo run --offline --locked -- bursts --threshold 10 tests/fixtures/app.log
```

```text
2026-01-15T00:01:00Z .. 2026-01-15T00:02:00Z  count: 10
     10 job <n> failed on sled<n>
```

## Read output and status

`summary` and `bursts` accept `--format json`. They emit one pretty JSON
document and a final newline. Summary objects contain `total_records`,
`unparsed_lines`, `first_timestamp`, `last_timestamp`, `levels`, `groups`,
`top_templates`, and `busiest_warn_minute`. Burst output wraps results in
`{ "bursts": [...] }`.

A template object contains `template`, `count`, `highest_level`, `first_seen`,
`last_seen`, and `example`. Time values are RFC 3339 strings or `null`. All
displayed timestamps use UTC.

Text reports escape control characters in groups, templates, and examples.
`filter` keeps raw bytes unchanged.

Logsift exits with status 0 on success. It exits with status 1 for argument,
input, output, timestamp-range, or resource-limit errors. It exits with status
2 when `--fail-on LEVEL` observes an eligible record at or above that level.

A downstream broken pipe stops `filter` immediately. It exits 0 after a broken
pipe unless it already observed a `--fail-on` match. It exits 2 in that case.

For `bursts`, eligibility requires a valid timestamp and a level at or above
`--level`. `--fail-on` applies to those eligible records. `--threshold` only
controls whether a window renders.

## Understand limits and templates

Logsift accepts at most 1 MiB per raw line, including the final newline.
`summary` counts longer lines as unparsed. Other commands skip those lines.
The reader discards excess bytes until the next newline without buffering them.

`summary` retains 10,000 named groups and an `<other>` group. It retains 10,000
named templates and an `<other>` template. It stores at most 100,000 warning
minutes. Template text and examples retain at most 512 bytes each. Group names
retain at most 512 bytes.

`bursts` retains at most 100,000 windows. Each window retains 10,000 named
templates and an `<other>` template. All windows together retain at most
100,000 template entries. Logsift returns a clear resource-limit error instead
of silently dropping a new window or template entry.

Templates replace UUIDs, valid IPv4 or IPv6 addresses, hexadecimal values, and
numbers in that order. IPv4 ports are included. Bracketed IPv6 ports are also
included. Clock values and MAC addresses are not treated as IP addresses.

Numbers include signs, decimals, unit suffixes, and compound units. For example,
`1h30m` and `1920x1080` both become `<n>`. Digits inside identifiers are
normalized while their word remains. For example, `sled7` becomes `sled<n>`.

Bare hexadecimal tokens need at least eight ASCII hex characters. They also
need at least one letter and one digit. Therefore, `a1b2c3d4` becomes `<hex>`,
while `10000000` becomes `<n>`.

Malformed JSON, non-object JSON, and objects without numeric `level` or string
`msg` are unparsed for `summary`. Other commands ignore them. Unknown numeric
levels map down to the closest bunyan level. Invalid timestamps do not reject
an otherwise valid record.

## License

MIT, copyright 2026 Xander M. Lopez. See [the license](LICENSE).

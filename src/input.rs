//! Streaming input discovery and gzip-aware, bounded line reading.

use anyhow::{Context, Result};
use flate2::read::MultiGzDecoder;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

/// Maximum raw bytes in one line, including its newline when present.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// An input line delivered to a command handler.
#[derive(Debug)]
pub enum InputLine {
    /// A complete raw line, including a trailing newline when present.
    Bytes(Vec<u8>),
    /// A line exceeded [`MAX_LINE_BYTES`] and was discarded without buffering it.
    Oversized,
}

/// Instructs the input reader whether it should continue reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineControl {
    /// Read the next line.
    Continue,
    /// Stop immediately without opening later input paths.
    Stop,
}

/// Expands input paths into sorted, deduplicated sources. `-` remains stdin.
///
/// Directory walks skip all symbolic-link entries. An explicitly supplied
/// symbolic link may name a non-directory stream, but a directory link is
/// rejected rather than traversed.
pub fn expand_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let requested = if paths.is_empty() {
        vec![PathBuf::from("-")]
    } else {
        paths.to_vec()
    };
    let mut expanded = Vec::new();
    for path in requested {
        if path == Path::new("-") {
            expanded.push(path);
            continue;
        }

        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect input {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            let target = fs::metadata(&path)
                .with_context(|| format!("inspect symbolic-link input {}", path.display()))?;
            if target.is_dir() {
                anyhow::bail!(
                    "input directory is a symbolic link and is not traversed: {}",
                    path.display()
                );
            }
            expanded.push(path);
        } else if metadata.is_dir() {
            walk(&path, &mut expanded)?;
        } else {
            // An explicit path may be a regular file, FIFO, or another readable
            // stream such as /dev/stdin. File::open reports unsupported sources.
            expanded.push(path);
        }
    }
    expanded.sort();
    expanded.dedup();
    Ok(expanded)
}

fn walk(path: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(path)
        .with_context(|| format!("read directory {}", path.display()))?
        .collect::<Result<Vec<_>, io::Error>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect directory entry in {}", path.display()))?;
        let entry_path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            walk(&entry_path, output)?;
        } else if file_type.is_file() {
            output.push(entry_path);
        }
    }
    Ok(())
}

/// Calls `handle` once for each bounded input line without loading a source.
///
/// Returning [`LineControl::Stop`] stops reading immediately. Gzip detection
/// replays every probe byte and supports concatenated gzip members.
pub fn for_each_line(
    paths: &[PathBuf],
    mut handle: impl FnMut(InputLine) -> Result<LineControl>,
) -> Result<()> {
    for path in expand_paths(paths)? {
        let control = if path == Path::new("-") {
            read_input(io::stdin().lock(), &mut handle).context("read stdin")?
        } else {
            let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
            read_input(file, &mut handle).with_context(|| format!("read {}", path.display()))?
        };
        if control == LineControl::Stop {
            return Ok(());
        }
    }
    Ok(())
}

fn read_input<R: Read>(
    reader: R,
    handle: &mut impl FnMut(InputLine) -> Result<LineControl>,
) -> Result<LineControl> {
    let (gzip, reader) = sniff_gzip(reader).context("inspect gzip prefix")?;
    if gzip {
        read_lines(BufReader::new(MultiGzDecoder::new(reader)), handle).context("decode gzip")
    } else {
        read_lines(BufReader::new(reader), handle)
    }
}

fn sniff_gzip<R: Read>(mut reader: R) -> io::Result<(bool, PrefixReader<R>)> {
    let mut bytes = [0_u8; 2];
    let mut used = 0;
    while used < bytes.len() {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(read) => used += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let prefix = bytes[..used].to_vec();
    let gzip = prefix.as_slice() == [0x1f, 0x8b];
    Ok((gzip, PrefixReader::new(prefix, reader)))
}

struct PrefixReader<R> {
    prefix: Vec<u8>,
    offset: usize,
    reader: R,
}

impl<R> PrefixReader<R> {
    fn new(prefix: Vec<u8>, reader: R) -> Self {
        Self {
            prefix,
            offset: 0,
            reader,
        }
    }
}

impl<R: Read> Read for PrefixReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let copied = remaining.len().min(buffer.len());
            buffer[..copied].copy_from_slice(&remaining[..copied]);
            self.offset += copied;
            return Ok(copied);
        }
        self.reader.read(buffer)
    }
}

fn read_lines(
    mut reader: impl BufRead,
    handle: &mut impl FnMut(InputLine) -> Result<LineControl>,
) -> Result<LineControl> {
    let mut line = Vec::new();
    let mut oversized = false;

    loop {
        let mut eof_event = None;
        let (consumed, ended_line) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                eof_event = if oversized {
                    Some(InputLine::Oversized)
                } else if line.is_empty() {
                    None
                } else {
                    Some(InputLine::Bytes(std::mem::take(&mut line)))
                };
                (0, false)
            } else {
                let newline = available.iter().position(|byte| *byte == b'\n');
                let consumed = newline.map_or(available.len(), |index| index + 1);
                if !oversized
                    && line
                        .len()
                        .checked_add(consumed)
                        .is_none_or(|length| length > MAX_LINE_BYTES)
                {
                    oversized = true;
                    line.clear();
                }
                if !oversized {
                    line.extend_from_slice(&available[..consumed]);
                }
                (consumed, newline.is_some())
            }
        };

        if let Some(event) = eof_event {
            return handle(event);
        }
        if consumed == 0 {
            return Ok(LineControl::Continue);
        }
        reader.consume(consumed);
        if ended_line {
            let event = if oversized {
                oversized = false;
                InputLine::Oversized
            } else {
                InputLine::Bytes(std::mem::take(&mut line))
            };
            if handle(event)? == LineControl::Stop {
                return Ok(LineControl::Stop);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InputLine, LineControl, MAX_LINE_BYTES, read_input, read_lines};
    use flate2::{Compression, write::GzEncoder};
    use std::io::{BufReader, Cursor, Read, Write};

    struct OneByteReader<R>(R);

    impl<R: Read> Read for OneByteReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let length = buffer.len().min(1);
            self.0.read(&mut buffer[..length])
        }
    }

    #[test]
    fn gzip_prefix_probe_replays_short_reads() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"first\nsecond\n").unwrap();
        let gzip = encoder.finish().unwrap();
        let mut lines = Vec::new();
        read_input(OneByteReader(Cursor::new(gzip)), &mut |line| {
            if let InputLine::Bytes(bytes) = line {
                lines.push(bytes);
            }
            Ok(LineControl::Continue)
        })
        .unwrap();
        assert_eq!(lines, [b"first\n".to_vec(), b"second\n".to_vec()]);
    }

    #[test]
    fn skips_oversized_line_without_losing_the_next_line() {
        let mut source = vec![b'x'; MAX_LINE_BYTES + 1];
        source.extend_from_slice(b"\nsmall\n");
        let mut lines = Vec::new();
        read_lines(
            BufReader::with_capacity(31, Cursor::new(source)),
            &mut |line| {
                lines.push(line);
                Ok(LineControl::Continue)
            },
        )
        .unwrap();
        assert!(matches!(lines.first(), Some(InputLine::Oversized)));
        assert!(matches!(lines.get(1), Some(InputLine::Bytes(bytes)) if bytes == b"small\n"));
    }

    #[test]
    fn handler_stop_does_not_read_later_lines() {
        let mut seen = 0;
        let control = read_lines(BufReader::new(Cursor::new(b"one\ntwo\n")), &mut |_| {
            seen += 1;
            Ok(LineControl::Stop)
        })
        .unwrap();
        assert_eq!(control, LineControl::Stop);
        assert_eq!(seen, 1);
    }
}

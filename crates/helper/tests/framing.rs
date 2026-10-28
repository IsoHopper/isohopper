// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::framing::{MAX_FRAME_BYTES, read_frame, write_frame};
use std::io::{self, Cursor, Read, Write};

struct FragmentedReader {
    bytes: Cursor<Vec<u8>>,
    interrupt: bool,
}
impl Read for FragmentedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if std::mem::replace(&mut self.interrupt, false) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.interrupt = true;
        let limit = buffer.len().min(2);
        self.bytes.read(&mut buffer[..limit])
    }
}

#[derive(Default)]
struct FragmentedWriter {
    bytes: Vec<u8>,
    interrupt: bool,
    fail_at: Option<usize>,
    fail_flush: bool,
    flushes: usize,
    writes: usize,
}
impl Write for FragmentedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if std::mem::replace(&mut self.interrupt, false) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.interrupt = true;
        let remaining = self.fail_at.unwrap_or(usize::MAX) - self.bytes.len();
        if remaining == 0 {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let count = buffer.len().min(3).min(remaining);
        self.bytes.extend_from_slice(&buffer[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn fragmented_interrupted_reads_leave_the_next_coalesced_frame_intact() {
    let mut reader = FragmentedReader {
        bytes: Cursor::new(b"\0\0\0\x03abc\0\0\0\x02de".to_vec()),
        interrupt: true,
    };
    assert_eq!(read_frame(&mut reader).unwrap(), Some(b"abc".to_vec()));
    assert_eq!(reader.bytes.position(), 7);
    assert_eq!(read_frame(&mut reader).unwrap(), Some(b"de".to_vec()));
    assert_eq!(reader.bytes.position(), 13);
    assert_eq!(read_frame(&mut reader).unwrap(), None);
}

#[test]
fn clean_eof_is_distinct_from_every_truncated_header_or_payload() {
    assert_eq!(read_frame(&mut &b""[..]).unwrap(), None);
    let frame = b"\0\0\0\x03abc";
    for end in 1..frame.len() {
        let error = read_frame(&mut &frame[..end]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "length {end}");
    }
}

#[test]
fn invalid_lengths_are_rejected_before_reading_any_payload() {
    struct HeaderOnly(Cursor<[u8; 4]>);
    impl Read for HeaderOnly {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(self.0.position() < 4, "invalid length reached payload read");
            self.0.read(buffer)
        }
    }
    for length in [0u32, MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
        let mut reader = HeaderOnly(Cursor::new(length.to_be_bytes()));
        assert_eq!(
            read_frame(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(reader.0.position(), 4);
    }
}

#[test]
fn minimum_and_maximum_frames_use_big_endian_length_and_one_flush() {
    for (payload, header) in [
        (vec![0xa5], [0, 0, 0, 1]),
        (vec![0xa5; MAX_FRAME_BYTES], [0, 1, 0, 0]),
    ] {
        let mut writer = FragmentedWriter::default();
        write_frame(&mut writer, &payload).unwrap();
        assert_eq!(&writer.bytes[..4], &header);
        assert_eq!(writer.flushes, 1);
        let mut input = Cursor::new(writer.bytes);
        assert_eq!(read_frame(&mut input).unwrap(), Some(payload));
        assert_eq!(read_frame(&mut input).unwrap(), None);
    }
}

#[test]
fn fragmented_interrupted_writes_complete_header_payload_and_flush() {
    let mut writer = FragmentedWriter {
        interrupt: true,
        ..Default::default()
    };
    write_frame(&mut writer, b"abcdef").unwrap();
    assert_eq!(writer.bytes, b"\0\0\0\x06abcdef");
    assert_eq!(writer.flushes, 1);
    write_frame(&mut writer, b"g").unwrap();
    assert_eq!(writer.bytes, b"\0\0\0\x06abcdef\0\0\0\x01g");
    assert_eq!(writer.flushes, 2);
}

#[test]
fn invalid_outbound_length_performs_no_write_or_flush() {
    for payload in [vec![], vec![0; MAX_FRAME_BYTES + 1]] {
        let mut writer = FragmentedWriter::default();
        assert_eq!(
            write_frame(&mut writer, &payload).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(writer.writes, 0);
        assert_eq!(writer.flushes, 0);
    }
}

#[test]
fn io_failures_are_not_reported_as_clean_eof_or_complete_frames() {
    struct FailingReader {
        prefix: Cursor<Vec<u8>>,
        failure: io::ErrorKind,
    }
    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.prefix.position() == self.prefix.get_ref().len() as u64 {
                return Err(self.failure.into());
            }
            self.prefix.read(buffer)
        }
    }
    for (prefix, failure) in [
        (vec![], io::ErrorKind::PermissionDenied),
        (vec![], io::ErrorKind::UnexpectedEof),
        (vec![0, 0], io::ErrorKind::PermissionDenied),
        (vec![0, 0, 0, 2, b'a'], io::ErrorKind::PermissionDenied),
    ] {
        let mut reader = FailingReader {
            prefix: Cursor::new(prefix),
            failure,
        };
        assert_eq!(read_frame(&mut reader).unwrap_err().kind(), failure);
    }
    for fail_at in [0, 2, 5] {
        let mut writer = FragmentedWriter {
            fail_at: Some(fail_at),
            ..Default::default()
        };
        assert_eq!(
            write_frame(&mut writer, b"abc").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(writer.bytes.len(), fail_at);
        assert_eq!(writer.flushes, 0);
    }
}

#[test]
fn zero_progress_write_and_failed_flush_are_errors() {
    struct ZeroWriter;
    impl Write for ZeroWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("incomplete frame was flushed")
        }
    }
    assert_eq!(
        write_frame(&mut ZeroWriter, b"abc").unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    let mut writer = FragmentedWriter {
        fail_flush: true,
        ..Default::default()
    };
    assert_eq!(
        write_frame(&mut writer, b"abc").unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(writer.bytes, b"\0\0\0\x03abc");
    assert_eq!(writer.flushes, 1);
}

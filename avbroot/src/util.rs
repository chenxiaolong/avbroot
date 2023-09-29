/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{fmt, path::Path};

use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};

pub const ZEROS: [u8; 16384] = [0u8; 16384];

/// A small wrapper to format a number as a size in bytes.
#[derive(Clone, Copy)]
pub struct NumBytes(pub usize);

impl fmt::Debug for NumBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 1 {
            write!(f, "<{:?} byte>", self.0)
        } else {
            write!(f, "<{:?} bytes>", self.0)
        }
    }
}

/// Check if a byte slice is all zeros.
pub fn is_zero(mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        let n = buf.len().min(ZEROS.len());
        if buf[..n] != ZEROS[..n] {
            return false;
        }

        buf = &buf[n..];
    }

    true
}

/// Read a protobuf message with no leading size field.
pub fn read_protobuf<'a, M: MessageRead<'a>>(data: &'a [u8]) -> quick_protobuf::Result<M> {
    let mut reader = BytesReader::from_bytes(data);
    M::from_reader(&mut reader, data)
}

/// Write a protobuf message with no leading size field.
pub fn write_protobuf<M: MessageWrite>(message: &M) -> quick_protobuf::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(message.get_size());
    let mut writer = Writer::new(&mut buf);
    message.write_message(&mut writer)?;
    Ok(buf)
}

/// Get the non-empty parent of a path. If the path has no parent in the string,
/// then `.` is returned. This does not perform any filesystem operations.
pub fn parent_path(path: &Path) -> &Path {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            return parent;
        }
    }

    Path::new(".")
}

/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::fmt;

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

/// A wrapper around a byte slice to format it as ASCII with invalid bytes
/// escaped as `\x##`.
#[derive(Clone)]
pub struct EscapedString<T: AsRef<[u8]>> {
    inner: T,
    quoted: bool,
}

impl<T: AsRef<[u8]>> EscapedString<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            quoted: true,
        }
    }

    pub fn new_unquoted(inner: T) -> Self {
        Self {
            inner,
            quoted: false,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: AsRef<[u8]>> fmt::Debug for EscapedString<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let escaped: String = self
            .inner
            .as_ref()
            .iter()
            .flat_map(|b| b.escape_ascii())
            .map(char::from)
            .collect();

        if self.quoted {
            write!(f, "\"")?;
        }

        write!(f, "{escaped}")?;

        if self.quoted {
            write!(f, "\"")?;
        }

        Ok(())
    }
}

impl<T: AsRef<[u8]>> fmt::Display for EscapedString<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
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

/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{fmt, path::Path};

use num_traits::PrimInt;

pub const ZEROS: [u8; 16384] = [0u8; 16384];

/// A small wrapper to format a number as a size in bytes.
#[derive(Clone, Copy)]
pub struct NumBytes<T: PrimInt>(pub T);

impl<T: PrimInt + fmt::Debug> fmt::Debug for NumBytes<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == T::one() {
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

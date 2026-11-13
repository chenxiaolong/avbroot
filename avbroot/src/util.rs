// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt::{self, Display},
    path::{Component, Path, PathBuf},
};

use num_traits::PrimInt;
use thiserror::Error;

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

/// Stores a precomputed [`Debug`] string.
#[derive(Clone)]
pub struct DebugString(String);

impl DebugString {
    pub fn new(value: impl fmt::Debug) -> Self {
        Self(format!("{value:?}"))
    }
}

impl fmt::Debug for DebugString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        return parent;
    }

    Path::new(".")
}

/// Path safety-related errors.
#[derive(Clone, Debug, Error)]
pub enum PathSafetyError {
    #[error("Path contains multiple components: {0:?}")]
    NotSingle(PathBuf),
    #[error("Path contains '..': {0:?}")]
    HasDotDot(PathBuf),
}

/// Join `parent` with `child`, disallowing unsafe child paths. Absolute child
/// paths are converted into relative paths and `..` components result in an
/// error.
pub fn path_join(
    parent: impl AsRef<Path>,
    child: impl AsRef<Path>,
) -> Result<PathBuf, PathSafetyError> {
    fn inner(parent: &Path, child: &Path) -> Result<PathBuf, PathSafetyError> {
        let mut result = parent.to_owned();

        for component in child.components() {
            match component {
                // Make absolute paths relative.
                Component::Prefix(_) | Component::RootDir | Component::CurDir => continue,
                // Unsafe path. We block this even if it wouldn't escape the parent.
                Component::ParentDir => {
                    return Err(PathSafetyError::HasDotDot(child.to_path_buf()));
                }
                Component::Normal(os_str) => result.push(os_str),
            }
        }

        Ok(result)
    }

    inner(parent.as_ref(), child.as_ref())
}

/// Ensure that the path has no directory components.
pub fn path_ensure_single(name: impl AsRef<Path>) -> Result<(), PathSafetyError> {
    fn inner(name: &Path) -> Result<(), PathSafetyError> {
        // Path::file_name() already checks for `.` and `..`.
        if name.file_name() != Some(name.as_os_str()) {
            return Err(PathSafetyError::NotSingle(name.to_path_buf()));
        }

        Ok(())
    }

    inner(name.as_ref())
}

/// Like [`path_join`], but ensures that the child path contains no directory
/// components with [`path_ensure_single`].
pub fn path_join_single(
    parent: impl AsRef<Path>,
    child: impl AsRef<Path>,
) -> Result<PathBuf, PathSafetyError> {
    path_ensure_single(child.as_ref())?;
    path_join(parent.as_ref(), child.as_ref())
}

/// Join arbitrary displayable items with a separator.
pub fn join(into_iter: impl IntoIterator<Item = impl Display>, sep: &str) -> String {
    use std::fmt::Write;

    let mut result = String::new();

    for (i, item) in into_iter.into_iter().enumerate() {
        if i > 0 {
            result.push_str(sep);
        }

        write!(result, "{item}").expect("Failed to allocate");
    }

    result
}

/// Sort arbitrary sequence of sortable items.
pub fn sort<T: Ord>(iter: impl Iterator<Item = T>) -> Vec<T> {
    let mut items = iter.collect::<Vec<_>>();
    items.sort();
    items
}

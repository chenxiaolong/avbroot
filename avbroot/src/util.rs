// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    cmp::Ordering,
    fmt::{self, Display},
    mem,
    ops::Range,
    path::{Component, Path, PathBuf},
};

use num_traits::{NumCast, PrimInt, Unsigned};
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

/// An error returned when a value exceeds a maximum allowed value.
#[derive(Clone, Debug, Error)]
#[error("{value} exceeds maximum size {max_inclusive}")]
pub struct SizeTooLargeError {
    pub value: u64,
    pub max_inclusive: u64,
}

/// Verify that unsigned size `value` does not exceed `max_inclusive` and then
/// return `value`.
pub fn check_size<T>(value: T, max_inclusive: T) -> Result<T, SizeTooLargeError>
where
    T: PrimInt + Unsigned,
{
    const {
        assert!(
            mem::size_of::<T>() <= 8,
            "Integer must be 64 bits or smaller"
        );
    }

    if value > max_inclusive {
        return Err(SizeTooLargeError {
            value: NumCast::from(value).unwrap(),
            max_inclusive: NumCast::from(max_inclusive).unwrap(),
        });
    }

    Ok(value)
}

/// Try to cast unsigned size `value` to unsigned type `T`. If it does not fit,
/// the error will indicate the maximum value.
pub fn try_cast_size<T, V>(value: V) -> Result<T, SizeTooLargeError>
where
    T: PrimInt + Unsigned,
    V: PrimInt + Unsigned,
{
    const {
        assert!(
            mem::size_of::<T>() <= 8,
            "Integer must be 64 bits or smaller"
        );
    }

    NumCast::from(value).ok_or_else(|| SizeTooLargeError {
        value: NumCast::from(value).unwrap(),
        max_inclusive: NumCast::from(T::max_value()).unwrap(),
    })
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

/// Sort and merge overlapping intervals.
pub fn merge_overlapping<T>(sections: &[Range<T>]) -> Vec<Range<T>>
where
    T: Ord + Clone + Copy,
{
    let mut sections = sections.to_vec();
    sections.sort_by_key(|r| (r.start, r.end));

    let mut result = Vec::<Range<T>>::new();

    for section in sections {
        if section.start >= section.end {
            continue;
        } else if let Some(last) = result.last_mut()
            && section.start <= last.end
        {
            last.end = last.end.max(section.end);
            continue;
        }

        result.push(section);
    }

    result
}

/// Binary search to determine if the needle overlaps any of the ranges.
pub fn ranges_overlaps<T>(ranges: &[Range<T>], needle: &Range<T>) -> bool
where
    T: Ord,
{
    if needle.start < needle.end {
        ranges
            .binary_search_by(|range| {
                if range.start > needle.end {
                    Ordering::Greater
                } else if range.end <= needle.start {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .is_ok()
    } else {
        false
    }
}

/// Binary search to determine if any of the ranges contain the needle.
pub fn ranges_contains<T>(ranges: &[Range<T>], needle: &T) -> bool
where
    T: Ord,
{
    ranges
        .binary_search_by(|range| {
            if range.start > *needle {
                Ordering::Greater
            } else if range.end <= *needle {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_size() {
        check_size(u64::MIN, u64::MIN).unwrap();
        check_size(u64::MAX, u64::MAX).unwrap();
        check_size(1u8, 2).unwrap();

        let err = check_size(u8::MAX, 0).unwrap_err();
        assert_eq!(err.value, 255);
        assert_eq!(err.max_inclusive, 0);
    }

    #[test]
    fn test_try_cast_size() {
        let value: u8 = try_cast_size(255u16).unwrap();
        assert_eq!(value, 255);

        let err = try_cast_size::<u8, _>(256u16).unwrap_err();
        assert_eq!(err.value, 256);
        assert_eq!(err.max_inclusive, 255);
    }

    #[test]
    fn test_ranges_overlaps() {
        assert!(!ranges_overlaps(&[0..4], &(0..0)));
        assert!(ranges_overlaps(&[0..4], &(0..4)));
        assert!(ranges_overlaps(&[0..4], &(1..4)));
        assert!(ranges_overlaps(&[0..4], &(0..3)));
        assert!(!ranges_overlaps(&[0..4], &(4..5)));
        assert!(ranges_overlaps(&[5..8], &(5..9)));
        assert!(ranges_overlaps(&[5..8], &(4..8)));
        assert!(ranges_overlaps(&[5..8], &(4..9)));
        assert!(ranges_overlaps(&[0..4, 5..8], &(4..5)));
        assert!(ranges_overlaps(&[0..4, 5..8], &(0..9)));
    }

    #[test]
    fn test_ranges_contains() {
        assert!(ranges_contains(&[0..4], &0));
        assert!(!ranges_contains(&[0..4], &4));
        assert!(!ranges_contains(&[0..4, 5..8], &4));
        assert!(ranges_contains(&[0..4, 5..8], &6));
    }
}

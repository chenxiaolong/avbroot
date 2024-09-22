// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{cmp::Ordering, fmt, ops::Range, path::Path};

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
        } else if let Some(last) = result.last_mut() {
            if section.start <= last.end {
                last.end = last.end.max(section.end);
                continue;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranges_overlaps() {
        assert_eq!(ranges_overlaps(&[0..4], &(0..0)), false);
        assert_eq!(ranges_overlaps(&[0..4], &(0..4)), true);
        assert_eq!(ranges_overlaps(&[0..4], &(1..4)), true);
        assert_eq!(ranges_overlaps(&[0..4], &(0..3)), true);
        assert_eq!(ranges_overlaps(&[0..4], &(4..5)), false);
        assert_eq!(ranges_overlaps(&[5..8], &(5..9)), true);
        assert_eq!(ranges_overlaps(&[5..8], &(4..8)), true);
        assert_eq!(ranges_overlaps(&[5..8], &(4..9)), true);
        assert_eq!(ranges_overlaps(&[0..4, 5..8], &(4..5)), true);
        assert_eq!(ranges_overlaps(&[0..4, 5..8], &(0..9)), true);
    }

    #[test]
    fn test_ranges_contains() {
        assert_eq!(ranges_contains(&[0..4], &0), true);
        assert_eq!(ranges_contains(&[0..4], &4), false);
        assert_eq!(ranges_contains(&[0..4, 5..8], &4), false);
        assert_eq!(ranges_contains(&[0..4, 5..8], &6), true);
    }
}

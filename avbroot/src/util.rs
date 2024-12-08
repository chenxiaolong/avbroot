// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    cmp::Ordering,
    fmt, mem,
    ops::{Bound, Range, RangeBounds},
    path::Path,
};

use num_traits::{NumCast, PrimInt};
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

/// A single bound in a range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntBound<T: PrimInt> {
    Included(T),
    Excluded(T),
}

/// A bounded primitive integer range. Unlike std's range types, this is a
/// single type that can represent open, closed, and half-open intervals.
#[derive(Clone, Copy, Debug)]
pub struct IntRange<T: PrimInt> {
    pub start: IntBound<T>,
    pub end: IntBound<T>,
}

impl<T: PrimInt> IntRange<T> {
    /// Returns [`None`] if the range bounds cannot be represented by `T`. If
    /// the start and end of `range` are unbounded, then it gets converted to
    /// [`IntBound::Included`] with `N`'s minimum or maximum value.
    pub fn new<N: PrimInt, R: RangeBounds<N>>(range: R) -> Option<Self> {
        let start = match range.start_bound() {
            Bound::Included(n) => IntBound::Included(T::from(*n)?),
            Bound::Excluded(n) => IntBound::Excluded(T::from(*n)?),
            Bound::Unbounded => IntBound::Included(T::from(N::min_value())?),
        };

        let end = match range.end_bound() {
            Bound::Included(n) => IntBound::Included(T::from(*n)?),
            Bound::Excluded(n) => IntBound::Excluded(T::from(*n)?),
            Bound::Unbounded => IntBound::Included(T::from(N::max_value())?),
        };

        Some(Self { start, end })
    }
}

impl<T: PrimInt + fmt::Display> fmt::Display for IntRange<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.start {
            IntBound::Included(n) => write!(f, "[{n}, ")?,
            IntBound::Excluded(n) => write!(f, "({n}, ")?,
        }

        match self.end {
            IntBound::Included(n) => write!(f, "{n}]"),
            IntBound::Excluded(n) => write!(f, "{n})"),
        }
    }
}

/// A non-generic type that can represent any 64-bit or smaller primitive
/// integer.
#[derive(Clone, Copy, Debug)]
pub enum LargeInt {
    Signed(i64),
    Unsigned(u64),
}

impl fmt::Display for LargeInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signed(n) => n.fmt(f),
            Self::Unsigned(n) => n.fmt(f),
        }
    }
}

/// A non-generic type that can represent any 64-bit or smaller primitive
/// integer range.
#[derive(Clone, Copy, Debug)]
pub enum LargeIntRange {
    Signed(IntRange<i64>),
    Unsigned(IntRange<u64>),
}

impl fmt::Display for LargeIntRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signed(r) => r.fmt(f),
            Self::Unsigned(r) => r.fmt(f),
        }
    }
}

/// An error returned when a value is not within a specific range.
#[derive(Clone, Copy, Debug, Error)]
#[error("Integer value {value} not in bounds: {range}")]
pub struct OutOfBoundsError {
    value: LargeInt,
    range: LargeIntRange,
}

/// Verify that `value` is within `bounds` and then return `value` if it is.
pub fn check_bounds<T: PrimInt>(
    value: T,
    bounds: impl RangeBounds<T>,
) -> Result<T, OutOfBoundsError> {
    const {
        assert!(
            mem::size_of::<T>() <= 8,
            "Integer must be 64 bits or smaller"
        );
    }

    if !bounds.contains(&value) {
        let value = if T::min_value() != T::zero() {
            LargeInt::Signed(NumCast::from(value).unwrap())
        } else {
            LargeInt::Unsigned(NumCast::from(value).unwrap())
        };

        let range = if T::min_value() != T::zero() {
            LargeIntRange::Signed(IntRange::new(bounds).unwrap())
        } else {
            LargeIntRange::Unsigned(IntRange::new(bounds).unwrap())
        };

        return Err(OutOfBoundsError { value, range });
    }

    Ok(value)
}

/// Try to cast `value` to primitive integer type `T`. If it does not fit, the
/// error will indicate the valid range of values.
pub fn try_cast<T: PrimInt, V: PrimInt>(value: V) -> Result<T, OutOfBoundsError> {
    const {
        assert!(
            mem::size_of::<T>() <= 8,
            "Integer must be 64 bits or smaller"
        );
    }

    NumCast::from(value).ok_or_else(|| {
        let value = if V::min_value() != V::zero() {
            LargeInt::Signed(NumCast::from(value).unwrap())
        } else {
            LargeInt::Unsigned(NumCast::from(value).unwrap())
        };

        let range = if T::min_value() != T::zero() {
            LargeIntRange::Signed(IntRange::new::<T, _>(..).unwrap())
        } else {
            LargeIntRange::Unsigned(IntRange::new::<T, _>(..).unwrap())
        };

        OutOfBoundsError { value, range }
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
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_int_range() {
        let range = IntRange::new::<u8, _>(..).unwrap();
        assert_eq!(range.start, IntBound::Included(u8::MIN));
        assert_eq!(range.end, IntBound::Included(u8::MAX));

        let range = IntRange::<i8>::new(-2i16..2i16).unwrap();
        assert_eq!(range.start, IntBound::Included(-2));
        assert_eq!(range.end, IntBound::Excluded(2));

        assert!(IntRange::<u8>::new::<u16, _>(..).is_none());
    }

    #[test]
    fn test_check_bounds() {
        check_bounds(i64::MIN, ..).unwrap();
        check_bounds(i64::MAX, ..).unwrap();
        check_bounds(u64::MIN, ..).unwrap();
        check_bounds(u64::MAX, ..).unwrap();
        check_bounds(0, -1..=1).unwrap();

        let err = check_bounds(i8::MAX, 0..=0).unwrap_err();
        assert_matches!(err.value, LargeInt::Signed(127));
        assert_matches!(
            err.range,
            LargeIntRange::Signed(IntRange {
                start: IntBound::Included(0),
                end: IntBound::Included(0),
            })
        );

        let err = check_bounds(u8::MAX, 0..=0).unwrap_err();
        assert_matches!(err.value, LargeInt::Unsigned(255));
        assert_matches!(
            err.range,
            LargeIntRange::Unsigned(IntRange {
                start: IntBound::Included(0),
                end: IntBound::Included(0),
            })
        );
    }

    #[test]
    fn test_try_cast() {
        let value: u8 = try_cast(255u16).unwrap();
        assert_eq!(value, 255);

        let err = try_cast::<i8, _>(256u16).unwrap_err();
        assert_matches!(err.value, LargeInt::Unsigned(256));
        assert_matches!(
            err.range,
            LargeIntRange::Signed(IntRange {
                start: IntBound::Included(-128),
                end: IntBound::Included(127),
            })
        );
    }

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

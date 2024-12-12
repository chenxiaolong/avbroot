// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    cmp::Ordering,
    fmt, mem,
    ops::{
        Bound, Range, RangeBounds, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
    },
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

#[derive(Clone, Hash, PartialEq, Eq)]
pub enum AnyRange<T> {
    Range(Range<T>),
    RangeFrom(RangeFrom<T>),
    RangeFull(RangeFull),
    RangeInclusive(RangeInclusive<T>),
    RangeTo(RangeTo<T>),
    RangeToInclusive(RangeToInclusive<T>),
}

impl<T> AnyRange<T> {
    pub fn with_bounds(start: Bound<T>, end: Bound<T>) -> Option<Self> {
        let result = match (start, end) {
            (Bound::Included(s), Bound::Excluded(e)) => Self::Range(s..e),
            (Bound::Included(s), Bound::Unbounded) => Self::RangeFrom(s..),
            (Bound::Unbounded, Bound::Unbounded) => Self::RangeFull(..),
            (Bound::Included(s), Bound::Included(e)) => Self::RangeInclusive(s..=e),
            (Bound::Unbounded, Bound::Excluded(e)) => Self::RangeTo(..e),
            (Bound::Unbounded, Bound::Included(e)) => Self::RangeToInclusive(..=e),
            (Bound::Excluded(_), _) => return None,
        };

        Some(result)
    }
}

impl<T: PartialOrd<T>> AnyRange<T> {
    pub fn contains<U>(&self, item: &U) -> bool
    where
        T: PartialOrd<U>,
        U: ?Sized + PartialOrd<T>,
    {
        <Self as RangeBounds<T>>::contains(self, item)
    }
}

impl<T: fmt::Debug> fmt::Debug for AnyRange<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Range(r) => r.fmt(f),
            Self::RangeFrom(r) => r.fmt(f),
            Self::RangeFull(r) => r.fmt(f),
            Self::RangeInclusive(r) => r.fmt(f),
            Self::RangeTo(r) => r.fmt(f),
            Self::RangeToInclusive(r) => r.fmt(f),
        }
    }
}

impl<T> RangeBounds<T> for AnyRange<T> {
    fn start_bound(&self) -> Bound<&T> {
        match self {
            Self::Range(r) => r.start_bound(),
            Self::RangeFrom(r) => r.start_bound(),
            Self::RangeFull(r) => r.start_bound(),
            Self::RangeInclusive(r) => r.start_bound(),
            Self::RangeTo(r) => r.start_bound(),
            Self::RangeToInclusive(r) => r.start_bound(),
        }
    }

    fn end_bound(&self) -> Bound<&T> {
        match self {
            Self::Range(r) => r.end_bound(),
            Self::RangeFrom(r) => r.end_bound(),
            Self::RangeFull(r) => r.end_bound(),
            Self::RangeInclusive(r) => r.end_bound(),
            Self::RangeTo(r) => r.end_bound(),
            Self::RangeToInclusive(r) => r.end_bound(),
        }
    }
}

impl<T> From<Range<T>> for AnyRange<T> {
    fn from(value: Range<T>) -> Self {
        Self::Range(value)
    }
}

impl<T> From<RangeFrom<T>> for AnyRange<T> {
    fn from(value: RangeFrom<T>) -> Self {
        Self::RangeFrom(value)
    }
}

impl<T> From<RangeFull> for AnyRange<T> {
    fn from(value: RangeFull) -> Self {
        Self::RangeFull(value)
    }
}

impl<T> From<RangeInclusive<T>> for AnyRange<T> {
    fn from(value: RangeInclusive<T>) -> Self {
        Self::RangeInclusive(value)
    }
}

impl<T> From<RangeTo<T>> for AnyRange<T> {
    fn from(value: RangeTo<T>) -> Self {
        Self::RangeTo(value)
    }
}

impl<T> From<RangeToInclusive<T>> for AnyRange<T> {
    fn from(value: RangeToInclusive<T>) -> Self {
        Self::RangeToInclusive(value)
    }
}

/// A non-generic type that can represent any 64-bit or smaller primitive
/// integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, PartialEq, Eq)]
pub enum LargeIntRange {
    Signed(AnyRange<i64>),
    Unsigned(AnyRange<u64>),
}

impl fmt::Debug for LargeIntRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signed(r) => r.fmt(f),
            Self::Unsigned(r) => r.fmt(f),
        }
    }
}

/// An error returned when a value is not within a specific range.
#[derive(Clone, Debug, Error)]
#[error("Integer value {value} not in bounds: {range:?}")]
pub struct OutOfBoundsError {
    value: LargeInt,
    range: LargeIntRange,
}

/// Verify that `value` is within `bounds` and then return `value` if it is.
pub fn check_bounds<T: PrimInt>(
    value: T,
    range: impl Into<AnyRange<T>>,
) -> Result<T, OutOfBoundsError> {
    const {
        assert!(
            mem::size_of::<T>() <= 8,
            "Integer must be 64 bits or smaller"
        );
    }

    let range = range.into();

    if !range.contains(&value) {
        let value = if T::min_value() != T::zero() {
            LargeInt::Signed(NumCast::from(value).unwrap())
        } else {
            LargeInt::Unsigned(NumCast::from(value).unwrap())
        };

        let range = if T::min_value() != T::zero() {
            let start = match range.start_bound() {
                Bound::Excluded(n) => Bound::Excluded(NumCast::from(*n).unwrap()),
                Bound::Included(n) => Bound::Included(NumCast::from(*n).unwrap()),
                Bound::Unbounded => Bound::Unbounded,
            };

            let end = match range.end_bound() {
                Bound::Excluded(n) => Bound::Excluded(NumCast::from(*n).unwrap()),
                Bound::Included(n) => Bound::Included(NumCast::from(*n).unwrap()),
                Bound::Unbounded => Bound::Unbounded,
            };

            LargeIntRange::Signed(AnyRange::with_bounds(start, end).unwrap())
        } else {
            let start = match range.start_bound() {
                Bound::Excluded(n) => Bound::Excluded(NumCast::from(*n).unwrap()),
                Bound::Included(n) => Bound::Included(NumCast::from(*n).unwrap()),
                Bound::Unbounded => Bound::Unbounded,
            };

            let end = match range.end_bound() {
                Bound::Excluded(n) => Bound::Excluded(NumCast::from(*n).unwrap()),
                Bound::Included(n) => Bound::Included(NumCast::from(*n).unwrap()),
                Bound::Unbounded => Bound::Unbounded,
            };

            LargeIntRange::Unsigned(AnyRange::with_bounds(start, end).unwrap())
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
            let min = NumCast::from(T::min_value()).unwrap();
            let max = NumCast::from(T::max_value()).unwrap();

            LargeIntRange::Signed((min..=max).into())
        } else {
            let min = NumCast::from(T::min_value()).unwrap();
            let max = NumCast::from(T::max_value()).unwrap();

            LargeIntRange::Unsigned((min..=max).into())
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
    use super::*;

    #[test]
    fn test_any_range() {
        let range = AnyRange::with_bounds(Bound::Included(0), Bound::Excluded(1)).unwrap();
        assert_eq!(range, AnyRange::from(0..1));

        let range = AnyRange::with_bounds(Bound::Included(0), Bound::Unbounded).unwrap();
        assert_eq!(range, AnyRange::from(0..));

        let range = AnyRange::<i32>::with_bounds(Bound::Unbounded, Bound::Unbounded).unwrap();
        assert_eq!(range, AnyRange::from(..));

        let range = AnyRange::with_bounds(Bound::Included(0), Bound::Included(1)).unwrap();
        assert_eq!(range, AnyRange::from(0..=1));

        let range = AnyRange::with_bounds(Bound::Unbounded, Bound::Excluded(1)).unwrap();
        assert_eq!(range, AnyRange::from(..1));

        let range = AnyRange::with_bounds(Bound::Unbounded, Bound::Included(1)).unwrap();
        assert_eq!(range, AnyRange::from(..=1));
    }

    #[test]
    fn test_check_bounds() {
        check_bounds(i64::MIN, ..).unwrap();
        check_bounds(i64::MAX, ..).unwrap();
        check_bounds(u64::MIN, ..).unwrap();
        check_bounds(u64::MAX, ..).unwrap();
        check_bounds(0, -1..=1).unwrap();

        let err = check_bounds(i8::MAX, 0..=0).unwrap_err();
        assert_eq!(err.value, LargeInt::Signed(127));
        assert_eq!(err.range, LargeIntRange::Signed(AnyRange::from(0..=0)));

        let err = check_bounds(u8::MAX, 0..=0).unwrap_err();
        assert_eq!(err.value, LargeInt::Unsigned(255));
        assert_eq!(err.range, LargeIntRange::Unsigned(AnyRange::from(0..=0)));
    }

    #[test]
    fn test_try_cast() {
        let value: u8 = try_cast(255u16).unwrap();
        assert_eq!(value, 255);

        let err = try_cast::<i8, _>(256u16).unwrap_err();
        assert_eq!(err.value, LargeInt::Unsigned(256));
        assert_eq!(err.range, LargeIntRange::Signed(AnyRange::from(-128..=127)));
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

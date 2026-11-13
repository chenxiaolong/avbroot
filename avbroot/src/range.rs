// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{cmp::Ordering, mem, ops::Range};

use num_traits::{NumCast, PrimInt, Unsigned};
use thiserror::Error;

/// An error returned when a value exceeds a maximum allowed value.
#[derive(Clone, Debug, Error)]
#[error("{value} exceeds maximum value {max_inclusive}")]
pub struct ValueTooLargeError {
    pub value: u64,
    pub max_inclusive: u64,
}

/// Verify that unsigned `value` does not exceed `max_inclusive` and then return
/// `value`.
pub fn ensure_within<T>(value: T, max_inclusive: T) -> Result<T, ValueTooLargeError>
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
        return Err(ValueTooLargeError {
            value: NumCast::from(value).unwrap(),
            max_inclusive: NumCast::from(max_inclusive).unwrap(),
        });
    }

    Ok(value)
}

/// Try to cast unsigned `value` to unsigned type `T`. If it does not fit, the
/// error will indicate the maximum value.
pub fn try_cast<T, V>(value: V) -> Result<T, ValueTooLargeError>
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

    NumCast::from(value).ok_or_else(|| ValueTooLargeError {
        value: NumCast::from(value).unwrap(),
        max_inclusive: NumCast::from(T::max_value()).unwrap(),
    })
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
/// `ranges` must be sorted and non-overlapping.
pub fn overlaps<T>(ranges: &[Range<T>], needle: &Range<T>) -> bool
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

/// Binary search to determine if any of the ranges contain the needle. `ranges`
/// must be sorted and non-overlapping.
pub fn contains<T>(ranges: &[Range<T>], needle: &T) -> bool
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
    fn test_ensure_within() {
        ensure_within(u64::MIN, u64::MIN).unwrap();
        ensure_within(u64::MAX, u64::MAX).unwrap();
        ensure_within(1u8, 2).unwrap();

        let err = ensure_within(u8::MAX, 0).unwrap_err();
        assert_eq!(err.value, 255);
        assert_eq!(err.max_inclusive, 0);
    }

    #[test]
    fn test_try_cast() {
        let value: u8 = try_cast(255u16).unwrap();
        assert_eq!(value, 255);

        let err = try_cast::<u8, _>(256u16).unwrap_err();
        assert_eq!(err.value, 256);
        assert_eq!(err.max_inclusive, 255);
    }

    #[test]
    fn test_merge_overlapping() {
        assert_eq!(merge_overlapping::<u8>(&[]), []);
        assert_eq!(merge_overlapping(&[0..1]), [0..1]);
        assert_eq!(merge_overlapping(&[3..4, 2..3, 0..1, 1..2]), [0..4]);
        assert_eq!(merge_overlapping(&[3..4, 2..3, 0..1, 1..2]), [0..4]);
        assert_eq!(merge_overlapping(&[1..4, 0..3]), [0..4]);
    }

    #[test]
    fn test_overlaps() {
        assert!(!overlaps(&[0..4], &(0..0)));
        assert!(overlaps(&[0..4], &(0..4)));
        assert!(overlaps(&[0..4], &(1..4)));
        assert!(overlaps(&[0..4], &(0..3)));
        assert!(!overlaps(&[0..4], &(4..5)));
        assert!(overlaps(&[5..8], &(5..9)));
        assert!(overlaps(&[5..8], &(4..8)));
        assert!(overlaps(&[5..8], &(4..9)));
        assert!(overlaps(&[0..4, 5..8], &(4..5)));
        assert!(overlaps(&[0..4, 5..8], &(0..9)));
    }

    #[test]
    fn test_contains() {
        assert!(contains(&[0..4], &0));
        assert!(!contains(&[0..4], &4));
        assert!(!contains(&[0..4, 5..8], &4));
        assert!(contains(&[0..4, 5..8], &6));
    }
}

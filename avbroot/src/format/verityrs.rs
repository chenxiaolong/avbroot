// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

// The gf256 library uses compile-time proc macro code generation. Since
// dm-verity supports RS(255, 231) through RS(255, 253), we'll generate RS
// implementations for every supported configuration.

#![allow(non_snake_case)]

use std::ops::RangeInclusive;

use gf256::rs::rs;

pub const SUPPORTED: RangeInclusive<u8> = 231..=253;

#[rs(block = 255, data = 231)]
mod rs255w231 {}
#[rs(block = 255, data = 232)]
mod rs255w232 {}
#[rs(block = 255, data = 233)]
mod rs255w233 {}
#[rs(block = 255, data = 234)]
mod rs255w234 {}
#[rs(block = 255, data = 235)]
mod rs255w235 {}
#[rs(block = 255, data = 236)]
mod rs255w236 {}
#[rs(block = 255, data = 237)]
mod rs255w237 {}
#[rs(block = 255, data = 238)]
mod rs255w238 {}
#[rs(block = 255, data = 239)]
mod rs255w239 {}
#[rs(block = 255, data = 240)]
mod rs255w240 {}
#[rs(block = 255, data = 241)]
mod rs255w241 {}
#[rs(block = 255, data = 242)]
mod rs255w242 {}
#[rs(block = 255, data = 243)]
mod rs255w243 {}
#[rs(block = 255, data = 244)]
mod rs255w244 {}
#[rs(block = 255, data = 245)]
mod rs255w245 {}
#[rs(block = 255, data = 246)]
mod rs255w246 {}
#[rs(block = 255, data = 247)]
mod rs255w247 {}
#[rs(block = 255, data = 248)]
mod rs255w248 {}
#[rs(block = 255, data = 249)]
mod rs255w249 {}
#[rs(block = 255, data = 250)]
mod rs255w250 {}
#[rs(block = 255, data = 251)]
mod rs255w251 {}
#[rs(block = 255, data = 252)]
mod rs255w252 {}
#[rs(block = 255, data = 253)]
mod rs255w253 {}

static FN_ENCODE: [fn(&mut [u8]); 23] = [
    rs255w231::encode,
    rs255w232::encode,
    rs255w233::encode,
    rs255w234::encode,
    rs255w235::encode,
    rs255w236::encode,
    rs255w237::encode,
    rs255w238::encode,
    rs255w239::encode,
    rs255w240::encode,
    rs255w241::encode,
    rs255w242::encode,
    rs255w243::encode,
    rs255w244::encode,
    rs255w245::encode,
    rs255w246::encode,
    rs255w247::encode,
    rs255w248::encode,
    rs255w249::encode,
    rs255w250::encode,
    rs255w251::encode,
    rs255w252::encode,
    rs255w253::encode,
];

pub fn fn_encode(rs_k: u8) -> fn(&mut [u8]) {
    assert!(SUPPORTED.contains(&rs_k), "Unsupported rs_k: {rs_k}");

    FN_ENCODE[usize::from(rs_k - SUPPORTED.start())]
}

static FN_IS_CORRECT: [fn(&[u8]) -> bool; 23] = [
    rs255w231::is_correct,
    rs255w232::is_correct,
    rs255w233::is_correct,
    rs255w234::is_correct,
    rs255w235::is_correct,
    rs255w236::is_correct,
    rs255w237::is_correct,
    rs255w238::is_correct,
    rs255w239::is_correct,
    rs255w240::is_correct,
    rs255w241::is_correct,
    rs255w242::is_correct,
    rs255w243::is_correct,
    rs255w244::is_correct,
    rs255w245::is_correct,
    rs255w246::is_correct,
    rs255w247::is_correct,
    rs255w248::is_correct,
    rs255w249::is_correct,
    rs255w250::is_correct,
    rs255w251::is_correct,
    rs255w252::is_correct,
    rs255w253::is_correct,
];

pub fn fn_is_correct(rs_k: u8) -> fn(&[u8]) -> bool {
    assert!(SUPPORTED.contains(&rs_k), "Unsupported rs_k: {rs_k}");

    FN_IS_CORRECT[usize::from(rs_k - SUPPORTED.start())]
}

// Each one of these has its own error type, but the functions can only fail one
// way (too many corrupt bytes), so just throw away the error and return an
// Option instead.
#[allow(clippy::type_complexity)]
static FN_CORRECT_ERRORS: [fn(&mut [u8]) -> Option<usize>; 23] = [
    |data: &mut [u8]| rs255w231::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w232::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w233::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w234::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w235::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w236::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w237::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w238::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w239::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w240::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w241::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w242::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w243::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w244::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w245::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w246::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w247::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w248::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w249::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w250::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w251::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w252::correct_errors(data).ok(),
    |data: &mut [u8]| rs255w253::correct_errors(data).ok(),
];

pub fn fn_correct_errors(rs_k: u8) -> fn(&mut [u8]) -> Option<usize> {
    assert!(SUPPORTED.contains(&rs_k), "Unsupported rs_k: {rs_k}");

    FN_CORRECT_ERRORS[usize::from(rs_k - SUPPORTED.start())]
}

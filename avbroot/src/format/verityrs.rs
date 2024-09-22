// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

// The gf256 library uses compile-time proc macro code generation. Since
// dm-verity supports RS(255, 231) through RS(255, 253), we'll generate RS
// implementations for every supported configuration.

#![allow(non_snake_case)]

use gf256::rs::rs;
use phf::phf_map;

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

pub static FN_ENCODE: phf::Map<u8, fn(&mut [u8])> = phf_map! {
    231u8 => rs255w231::encode,
    232u8 => rs255w232::encode,
    233u8 => rs255w233::encode,
    234u8 => rs255w234::encode,
    235u8 => rs255w235::encode,
    236u8 => rs255w236::encode,
    237u8 => rs255w237::encode,
    238u8 => rs255w238::encode,
    239u8 => rs255w239::encode,
    240u8 => rs255w240::encode,
    241u8 => rs255w241::encode,
    242u8 => rs255w242::encode,
    243u8 => rs255w243::encode,
    244u8 => rs255w244::encode,
    245u8 => rs255w245::encode,
    246u8 => rs255w246::encode,
    247u8 => rs255w247::encode,
    248u8 => rs255w248::encode,
    249u8 => rs255w249::encode,
    250u8 => rs255w250::encode,
    251u8 => rs255w251::encode,
    252u8 => rs255w252::encode,
    253u8 => rs255w253::encode,
};

pub static FN_IS_CORRECT: phf::Map<u8, fn(&[u8]) -> bool> = phf_map! {
    231u8 => rs255w231::is_correct,
    232u8 => rs255w232::is_correct,
    233u8 => rs255w233::is_correct,
    234u8 => rs255w234::is_correct,
    235u8 => rs255w235::is_correct,
    236u8 => rs255w236::is_correct,
    237u8 => rs255w237::is_correct,
    238u8 => rs255w238::is_correct,
    239u8 => rs255w239::is_correct,
    240u8 => rs255w240::is_correct,
    241u8 => rs255w241::is_correct,
    242u8 => rs255w242::is_correct,
    243u8 => rs255w243::is_correct,
    244u8 => rs255w244::is_correct,
    245u8 => rs255w245::is_correct,
    246u8 => rs255w246::is_correct,
    247u8 => rs255w247::is_correct,
    248u8 => rs255w248::is_correct,
    249u8 => rs255w249::is_correct,
    250u8 => rs255w250::is_correct,
    251u8 => rs255w251::is_correct,
    252u8 => rs255w252::is_correct,
    253u8 => rs255w253::is_correct,
};

// Each one of these has its own error type, but the functions can only fail one
// way (too many corrupt bytes), so just throw away the error and return an
// Option instead.
#[allow(clippy::type_complexity)]
pub static FN_CORRECT_ERRORS: phf::Map<u8, fn(&mut [u8]) -> Option<usize>> = phf_map! {
    231u8 => |data: &mut [u8]| rs255w231::correct_errors(data).ok(),
    232u8 => |data: &mut [u8]| rs255w232::correct_errors(data).ok(),
    233u8 => |data: &mut [u8]| rs255w233::correct_errors(data).ok(),
    234u8 => |data: &mut [u8]| rs255w234::correct_errors(data).ok(),
    235u8 => |data: &mut [u8]| rs255w235::correct_errors(data).ok(),
    236u8 => |data: &mut [u8]| rs255w236::correct_errors(data).ok(),
    237u8 => |data: &mut [u8]| rs255w237::correct_errors(data).ok(),
    238u8 => |data: &mut [u8]| rs255w238::correct_errors(data).ok(),
    239u8 => |data: &mut [u8]| rs255w239::correct_errors(data).ok(),
    240u8 => |data: &mut [u8]| rs255w240::correct_errors(data).ok(),
    241u8 => |data: &mut [u8]| rs255w241::correct_errors(data).ok(),
    242u8 => |data: &mut [u8]| rs255w242::correct_errors(data).ok(),
    243u8 => |data: &mut [u8]| rs255w243::correct_errors(data).ok(),
    244u8 => |data: &mut [u8]| rs255w244::correct_errors(data).ok(),
    245u8 => |data: &mut [u8]| rs255w245::correct_errors(data).ok(),
    246u8 => |data: &mut [u8]| rs255w246::correct_errors(data).ok(),
    247u8 => |data: &mut [u8]| rs255w247::correct_errors(data).ok(),
    248u8 => |data: &mut [u8]| rs255w248::correct_errors(data).ok(),
    249u8 => |data: &mut [u8]| rs255w249::correct_errors(data).ok(),
    250u8 => |data: &mut [u8]| rs255w250::correct_errors(data).ok(),
    251u8 => |data: &mut [u8]| rs255w251::correct_errors(data).ok(),
    252u8 => |data: &mut [u8]| rs255w252::correct_errors(data).ok(),
    253u8 => |data: &mut [u8]| rs255w253::correct_errors(data).ok(),
};

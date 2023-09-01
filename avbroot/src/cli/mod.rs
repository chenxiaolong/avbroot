/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

pub mod args;
pub mod avb;
pub mod boot;
pub mod completion;
pub mod key;
pub mod ota;
pub mod ramdisk;

macro_rules! status {
    ($($arg:tt)*) => {
        println!("\x1b[1m[*] {}\x1b[0m", format!($($arg)*))
    }
}

macro_rules! warning {
    ($($arg:tt)*) => {
        println!("\x1b[1;31m[WARNING] {}\x1b[0m", format!($($arg)+))
    }
}

pub(crate) use status;
pub(crate) use warning;

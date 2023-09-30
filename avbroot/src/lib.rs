/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

//! Since avbroot is primarily an application and not a library, the semver
//! versioning covers the CLI only. All Rust APIs can change at any time, even
//! in patch releases.
//!
//! The CLI source files use concrete types wherever possible for simplicity,
//! while the "library"-style source files aim to be generic.

// We use pb-rs' nostd mode. See build.rs.
extern crate alloc;

pub mod boot;
pub mod cli;
pub mod crypto;
pub mod escape;
pub mod format;
pub mod octal;
pub mod protobuf;
pub mod stream;
pub mod util;

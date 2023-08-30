/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use anyhow::Result;

fn main() -> Result<()> {
    // Set up a cancel signal so we can properly clean up any temporary files.
    let cancel_signal = Arc::new(AtomicBool::new(false));
    {
        let signal = cancel_signal.clone();

        ctrlc::set_handler(move || {
            signal.store(true, Ordering::SeqCst);
        })
        .expect("Failed to set signal handler");
    }

    avbroot::cli::args::main(&cancel_signal)
}

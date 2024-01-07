/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tracing::error;

static LOGGING_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn main() {
    // Set up a cancel signal so we can properly clean up any temporary files.
    let cancel_signal = Arc::new(AtomicBool::new(false));
    {
        let signal = cancel_signal.clone();

        ctrlc::set_handler(move || {
            signal.store(true, Ordering::SeqCst);
        })
        .expect("Failed to set signal handler");
    }

    match avbroot::cli::args::main(&LOGGING_INITIALIZED, &cancel_signal) {
        Ok(_) => {}
        Err(e) => {
            if LOGGING_INITIALIZED.load(Ordering::SeqCst) {
                error!("{e:?}");
            } else {
                eprintln!("{e:?}");
            }
            std::process::exit(1);
        }
    }
}

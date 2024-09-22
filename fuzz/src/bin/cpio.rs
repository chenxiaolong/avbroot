// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

#[cfg(not(windows))]
mod fuzz {
    use std::{io::Cursor, sync::atomic::AtomicBool};

    use avbroot::format::cpio;
    use honggfuzz::fuzz;

    pub fn main() {
        loop {
            fuzz!(|data: &[u8]| {
                let cancel_signal = AtomicBool::new(false);
                let reader = Cursor::new(data);
                let _ = cpio::load(reader, true, &cancel_signal);
            });
        }
    }
}

fn main() {
    #[cfg(not(windows))]
    fuzz::main();
}

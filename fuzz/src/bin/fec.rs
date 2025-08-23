// SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

#[cfg(not(windows))]
mod fuzz {
    use std::{io::Cursor, sync::atomic::AtomicBool};

    use avbroot::{
        format::fec::FecImage,
        stream::{FromReader, MutexFile, UserPosFile, WriteZerosExt},
    };
    use honggfuzz::fuzz;

    pub fn main() {
        loop {
            fuzz!(|data: &[u8]| {
                let cancel_signal = AtomicBool::new(false);

                let reader = Cursor::new(data);
                if let Ok(fec) = FecImage::from_reader(reader) {
                    let input = MutexFile::new(Cursor::new(Vec::new()));

                    // Allow verify() to get further, but don't blow up the host
                    // with excessive memory usage.
                    if fec.data_size < 64 * 1024 * 1024 {
                        UserPosFile::new(&input)
                            .write_zeros_exact(fec.data_size)
                            .unwrap();
                    }

                    let _ = fec.verify(&input, &cancel_signal);
                }
            });
        }
    }
}

fn main() {
    #[cfg(not(windows))]
    fuzz::main();
}

#[cfg(not(windows))]
mod fuzz {
    use std::io::Cursor;

    use avbroot::format::cpio;
    use honggfuzz::fuzz;

    pub fn main() {
        loop {
            fuzz!(|data: &[u8]| {
                let reader = Cursor::new(data);
                let _ = cpio::load(reader, true);
            });
        }
    }
}

fn main() {
    #[cfg(not(windows))]
    fuzz::main();
}

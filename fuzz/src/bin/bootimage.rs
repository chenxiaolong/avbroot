#[cfg(not(windows))]
mod fuzz {
    use std::io::Cursor;

    use avbroot::{format::bootimage::BootImage, stream::FromReader};
    use honggfuzz::fuzz;

    pub fn main() {
        loop {
            fuzz!(|data: &[u8]| {
                let reader = Cursor::new(data);
                let _ = BootImage::from_reader(reader);
            });
        }
    }
}

fn main() {
    #[cfg(not(windows))]
    fuzz::main();
}

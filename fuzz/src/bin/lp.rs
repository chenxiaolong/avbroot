#[cfg(not(windows))]
mod fuzz {
    use std::io::Cursor;

    use avbroot::{format::lp::Metadata, stream::FromReader};
    use honggfuzz::fuzz;

    pub fn main() {
        loop {
            fuzz!(|data: &[u8]| {
                let reader = Cursor::new(data);
                let _ = Metadata::from_reader(reader);
            });
        }
    }
}

fn main() {
    #[cfg(not(windows))]
    fuzz::main();
}

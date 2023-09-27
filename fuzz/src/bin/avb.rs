#[cfg(not(windows))]
mod fuzz {
    use std::io::Cursor;

    use avbroot::format::avb;
    use honggfuzz::fuzz;

    pub fn main() {
        loop {
            fuzz!(|data: &[u8]| {
                let reader = Cursor::new(data);
                let _ = avb::load_image(reader);
            });
        }
    }
}

fn main() {
    #[cfg(not(windows))]
    fuzz::main();
}

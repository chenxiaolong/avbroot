#[cfg(not(windows))]
mod fuzz {
    use std::io::{self, Cursor};

    use avbroot::format::sparse::{ChunkData, CrcMode, SparseReader};
    use honggfuzz::fuzz;

    pub fn main() {
        loop {
            fuzz!(|data: &[u8]| {
                let reader = Cursor::new(data);
                if let Ok(mut sparse_reader) = SparseReader::new(reader, CrcMode::Ignore) {
                    while let Ok(Some(chunk)) = sparse_reader.next_chunk() {
                        if chunk.data == ChunkData::Data {
                            let _ = io::copy(&mut sparse_reader, &mut io::sink());
                        }
                    }
                }
            });
        }
    }
}

fn main() {
    #[cfg(not(windows))]
    fuzz::main();
}

// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::io::{self, Read, Seek, Write};

use num_traits::PrimInt;

use crate::stream::{ReadDiscardExt, WriteZerosExt};

/// Calculate the amount of padding that needs to be added to align the
/// specified offset to a page boundary.
pub fn calc<N: PrimInt>(offset: N, page_size: N) -> N {
    let r = offset % page_size;
    if r == N::zero() {
        N::zero()
    } else {
        page_size - r
    }
}

/// Round to the next multiple of the page size.
pub fn round<N: PrimInt>(offset: N, page_size: N) -> Option<N> {
    let remain = calc(offset, page_size);
    offset.checked_add(&remain)
}

/// Read and discard data until the next multiple of the page size. [`Seek`] is
/// only used for querying the file position.
pub fn read_discard(mut reader: impl Read + Seek, page_size: u64) -> io::Result<u64> {
    let pos = reader.stream_position()?;
    let padding = calc(pos, page_size);

    reader.read_discard_exact(padding)?;

    Ok(padding)
}

/// Write zeros until the next multiple of the page size. [`Seek`] is only used
/// for querying the file position.
pub fn write_zeros(mut writer: impl Write + Seek, page_size: u64) -> io::Result<u64> {
    let pos = writer.stream_position()?;
    let padding = calc(pos, page_size);

    writer.write_zeros_exact(padding)?;

    Ok(padding)
}

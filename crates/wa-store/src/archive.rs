use anyhow::{Context, Result, bail, ensure};
use std::io::Read;

/// Magic bytes identifying the two archive envelopes `restore` accepts, so the
/// decompressor is chosen by content (not a filename/extension a caller controls).
const XZ_MAGIC: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0x00];
const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
// xz -9 uses a 64 MiB dictionary; leave room for the decoder's fixed state.
const MAX_XZ_MEMORY_KIB: u32 = 65 * 1024;

/// Decompress a whole archive into memory, capped at `max_unpacked` (bounds a
/// decompression bomb before the tar is even parsed). The compressor is picked by magic
/// bytes so a caller can't mislabel the payload via a filename/extension.
pub(crate) fn decompress(archive: &[u8], max_unpacked: u64) -> Result<Vec<u8>> {
    if archive.starts_with(XZ_MAGIC) {
        decompress_xz(archive, max_unpacked, MAX_XZ_MEMORY_KIB)
    } else if archive.starts_with(GZIP_MAGIC) {
        let mut buf = Vec::new();
        // +1 so a stream that fills exactly to the cap and keeps going is caught.
        let read = flate2::read::GzDecoder::new(archive)
            .take(max_unpacked + 1)
            .read_to_end(&mut buf)
            .context("gunzip archive")? as u64;
        bomb_guard(read > max_unpacked, max_unpacked)?;
        Ok(buf)
    } else {
        bail!("archive is neither xz nor gzip (unrecognized magic bytes)")
    }
}

pub(crate) fn decompress_xz(
    archive: &[u8],
    max_unpacked: u64,
    memory_limit_kib: u32,
) -> Result<Vec<u8>> {
    let mut decoder = lzma_rust2::XzStream::new_mem_limit(false, memory_limit_kib);
    let mut input = archive;
    let mut out = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let result = decoder
            .process(input, &mut buffer, lzma_rust2::Action::Finish)
            .context("decompress xz archive")?;
        input = &input[result.bytes_consumed..];
        bomb_guard(
            out.len() as u64 + result.bytes_produced as u64 > max_unpacked,
            max_unpacked,
        )?;
        out.extend_from_slice(&buffer[..result.bytes_produced]);
        if result.status == lzma_rust2::Status::StreamEnd {
            ensure!(input.is_empty(), "xz archive has trailing data");
            return Ok(out);
        }
        ensure!(
            result.bytes_consumed != 0 || result.bytes_produced != 0,
            "xz decoder made no progress"
        );
    }
}

fn bomb_guard(overflowed: bool, max_unpacked: u64) -> Result<()> {
    if overflowed {
        bail!(
            "archive unpacks to more than {max_unpacked} bytes — refusing (possible decompression bomb)"
        );
    }
    Ok(())
}

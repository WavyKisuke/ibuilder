//! Bounds-checked metadata reader for Unreal Engine IoStore TOC files.
//!
//! This is the first layer of Unreal shader support. It identifies shader-library
//! and shader-code chunks without decoding game payloads. Payload decompression,
//! directory-index parsing, Pak files, and shader-library decoding are separate
//! follow-up layers.

use std::fmt;

pub const TOC_MAGIC: &[u8; 16] = b"-==--==--==--==-";
pub const HEADER_SIZE: usize = 144;
pub const CHUNK_SHADER_LIBRARY: u8 = 8;
pub const CHUNK_SHADER_CODE: u8 = 9;
pub const CHUNK_EXPORT_BUNDLE_UE5: u8 = 1;
pub const CHUNK_EXPORT_BUNDLE_UE427: u8 = 2;
pub const ENCRYPTION_METHOD_NONE: u8 = 0;
pub const ENCRYPTION_METHOD_AES: u8 = 1;
pub const ENCRYPTION_METHOD_AES_CTR: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoStoreError(pub String);

impl fmt::Display for IoStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for IoStoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkId {
    pub id: u64,
    pub index: u16,
    pub padding: u8,
    pub kind: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRange {
    /// Byte offset in the uncompressed IoStore stream.
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionBlock {
    /// Byte offset in the .ucas partition.
    pub offset: u64,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    /// Zero means stored; other values index the compression method table.
    pub method: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoStoreToc {
    pub version: u8,
    pub container_id: u64,
    pub flags: u8,
    pub encryption_method: u8,
    pub directory_index_size: u32,
    pub block_size: u32,
    pub partition_count: u32,
    pub partition_size: u64,
    pub chunks: Vec<(ChunkId, ChunkRange)>,
    pub blocks: Vec<CompressionBlock>,
    /// Per-block (and optional directory-index) 96-bit IVs for version-10 AES-CTR.
    pub encryption_ivs: Vec<[u8; 12]>,
    pub compression_methods: Vec<String>,
}

fn fail(why: &str) -> IoStoreError {
    IoStoreError(why.to_string())
}
fn le_u32(b: &[u8], at: usize) -> Result<u32, IoStoreError> {
    let s = b
        .get(at..at + 4)
        .ok_or_else(|| fail("truncated IoStore header"))?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}
fn le_u64(b: &[u8], at: usize) -> Result<u64, IoStoreError> {
    let s = b
        .get(at..at + 8)
        .ok_or_else(|| fail("truncated IoStore header"))?;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}
fn be_u40(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |v, x| (v << 8) | u64::from(*x))
}
fn le_u40(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |v, x| (v << 8) | u64::from(*x))
}
fn le_u24(b: &[u8]) -> u32 {
    u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16)
}
fn section_end(
    start: usize,
    count: usize,
    width: usize,
    total: usize,
) -> Result<usize, IoStoreError> {
    let end = start
        .checked_add(
            count
                .checked_mul(width)
                .ok_or_else(|| fail("IoStore section size overflow"))?,
        )
        .ok_or_else(|| fail("IoStore section offset overflow"))?;
    if end > total {
        return Err(fail("truncated IoStore TOC section"));
    }
    Ok(end)
}

impl IoStoreToc {
    /// Parse the fixed header, chunk table, compression blocks, and method names.
    /// Unknown trailing sections (signatures and directory indexes) are left untouched.
    pub fn parse(data: &[u8]) -> Result<Self, IoStoreError> {
        if data.len() < HEADER_SIZE {
            return Err(fail("truncated IoStore TOC header"));
        }
        if data.get(..16) != Some(TOC_MAGIC.as_slice()) {
            return Err(fail("invalid IoStore TOC magic"));
        }

        let version = data[16];
        if version == 0 || version > 10 {
            return Err(fail("unsupported IoStore TOC version"));
        }
        let header_size = le_u32(data, 20)? as usize;
        let entry_count = le_u32(data, 24)? as usize;
        let block_count = le_u32(data, 28)? as usize;
        let block_entry_size = le_u32(data, 32)? as usize;
        let method_count = le_u32(data, 36)? as usize;
        let method_name_len = le_u32(data, 40)? as usize;
        let block_size = le_u32(data, 44)?;
        let directory_index_size = le_u32(data, 48)?;
        // Partition metadata was added after the original single-partition TOC versions.
        // Older containers use one partition spanning the full addressable range.
        let partition_count = if version >= 3 { le_u32(data, 52)? } else { 1 };
        if header_size != HEADER_SIZE || block_entry_size != 12 || block_size == 0 {
            return Err(fail("invalid IoStore TOC header dimensions"));
        }
        // Bound allocations by the actual file size before reserving vectors.
        if entry_count > data.len() / 22
            || block_count > data.len() / 12
            || method_count > 64
            || method_name_len > 256
        {
            return Err(fail("unreasonable IoStore TOC counts"));
        }

        let container_id = le_u64(data, 56)?;
        let flags = data[80];
        // Before TOC v10, encrypted containers use AES-ECB and have no IV table.
        let encryption_method = if version >= 10 {
            data[81]
        } else if flags & 0x02 != 0 {
            ENCRYPTION_METHOD_AES
        } else {
            ENCRYPTION_METHOD_NONE
        };
        if version >= 10
            && !matches!(
                encryption_method,
                ENCRYPTION_METHOD_NONE | ENCRYPTION_METHOD_AES | ENCRYPTION_METHOD_AES_CTR
            )
        {
            return Err(fail("unsupported IoStore encryption method"));
        }
        let partition_size = if version >= 3 {
            le_u64(data, 88)?
        } else {
            u64::MAX
        };
        let seed_count = if version >= 4 {
            le_u32(data, 84)? as usize
        } else {
            0
        };
        let no_hash_count = if version >= 5 {
            le_u32(data, 96)? as usize
        } else {
            0
        };

        let mut at = HEADER_SIZE;
        let ids_end = section_end(at, entry_count, 12, data.len())?;
        let ids = &data[at..ids_end];
        at = ids_end;
        let ranges_end = section_end(at, entry_count, 10, data.len())?;
        let ranges = &data[at..ranges_end];
        at = ranges_end;
        at = section_end(at, seed_count, 4, data.len())?;
        at = section_end(at, no_hash_count, 4, data.len())?;
        let blocks_end = section_end(at, block_count, 12, data.len())?;
        let block_bytes = &data[at..blocks_end];
        at = blocks_end;
        let iv_count = if version >= 10
            && flags & 0x02 != 0
            && encryption_method == ENCRYPTION_METHOD_AES_CTR
        {
            block_count + usize::from(flags & 0x08 != 0)
        } else {
            0
        };
        let iv_end = section_end(at, iv_count, 12, data.len())?;
        let iv_bytes = &data[at..iv_end];
        at = iv_end;
        let methods_end = section_end(at, method_count, method_name_len, data.len())?;
        let method_bytes = &data[at..methods_end];

        let mut chunks = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let id = &ids[i * 12..i * 12 + 12];
            let range = &ranges[i * 10..i * 10 + 10];
            chunks.push((
                ChunkId {
                    id: u64::from_le_bytes(id[0..8].try_into().unwrap()),
                    index: u16::from_be_bytes(id[8..10].try_into().unwrap()),
                    padding: id[10],
                    kind: id[11],
                },
                ChunkRange {
                    offset: be_u40(&range[..5]),
                    length: be_u40(&range[5..]),
                },
            ));
        }

        let mut blocks = Vec::with_capacity(block_count);
        for i in 0..block_count {
            let b = &block_bytes[i * 12..i * 12 + 12];
            blocks.push(CompressionBlock {
                offset: le_u40(&b[..5]),
                compressed_size: le_u24(&b[5..8]),
                uncompressed_size: le_u24(&b[8..11]),
                method: b[11],
            });
        }

        let mut encryption_ivs = Vec::with_capacity(iv_count);
        for i in 0..iv_count {
            let mut iv = [0u8; 12];
            iv.copy_from_slice(&iv_bytes[i * 12..(i + 1) * 12]);
            encryption_ivs.push(iv);
        }

        let mut compression_methods = Vec::with_capacity(method_count);
        for i in 0..method_count {
            let raw = &method_bytes[i * method_name_len..(i + 1) * method_name_len];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            compression_methods.push(String::from_utf8_lossy(&raw[..end]).trim().to_string());
        }

        Ok(Self {
            version,
            container_id,
            flags,
            encryption_method,
            directory_index_size,
            block_size,
            partition_count,
            partition_size,
            chunks,
            blocks,
            encryption_ivs,
            compression_methods,
        })
    }

    pub fn shader_chunk_count(&self) -> usize {
        if self.version < 4 {
            return 0;
        }
        self.chunks
            .iter()
            .filter(|(id, _)| id.kind == CHUNK_SHADER_LIBRARY || id.kind == CHUNK_SHADER_CODE)
            .count()
    }

    pub fn export_bundle_chunk_count(&self) -> usize {
        self.chunks
            .iter()
            .filter(|(id, _)| {
                (self.version >= 4 && id.kind == CHUNK_EXPORT_BUNDLE_UE5)
                    || (self.version <= 3 && id.kind == CHUNK_EXPORT_BUNDLE_UE427)
            })
            .count()
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & 0x02 != 0
    }
    pub fn is_indexed(&self) -> bool {
        self.flags & 0x08 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut b = vec![0u8; HEADER_SIZE];
        b[..16].copy_from_slice(TOC_MAGIC);
        // Reserve the chunk-ID table before writing IDs at the end of the header.
        b.resize(HEADER_SIZE + 24, 0);
        b[16] = 8;
        b[20..24].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        b[24..28].copy_from_slice(&2u32.to_le_bytes());
        b[28..32].copy_from_slice(&1u32.to_le_bytes());
        b[32..36].copy_from_slice(&12u32.to_le_bytes());
        b[36..40].copy_from_slice(&1u32.to_le_bytes());
        b[40..44].copy_from_slice(&8u32.to_le_bytes());
        b[44..48].copy_from_slice(&65536u32.to_le_bytes());
        b[56..64].copy_from_slice(&123u64.to_le_bytes());
        b[84..88].copy_from_slice(&1u32.to_le_bytes());
        b[88..96].copy_from_slice(&0x10000u64.to_le_bytes());
        b[96..100].copy_from_slice(&1u32.to_le_bytes());
        // Two chunk IDs: shader library (8) and shader code (9).
        for (i, kind) in [8u8, 9].into_iter().enumerate() {
            let p = HEADER_SIZE + i * 12;
            b[p..p + 8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            b[p + 8..p + 10].copy_from_slice(&1u16.to_be_bytes());
            b[p + 11] = kind;
        }
        b.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0, 0, 16]);
        b.extend_from_slice(&[0, 0, 0, 0, 2, 0, 0, 0, 0, 32]);
        // perfect-hash seed and overflow entries
        b.extend_from_slice(&[0; 8]);
        // one uncompressed block
        b.extend_from_slice(&[0, 0, 0, 0, 0, 16, 0, 0, 16, 0, 0, 0]);
        b.extend_from_slice(b"None\0\0\0\0");
        b
    }

    #[test]
    fn parses_shader_chunk_metadata() {
        let toc = IoStoreToc::parse(&fixture()).unwrap();
        assert_eq!(toc.version, 8);
        assert_eq!(toc.container_id, 123);
        assert_eq!(toc.shader_chunk_count(), 2);
        assert_eq!(toc.export_bundle_chunk_count(), 0);
        assert_eq!(toc.blocks.len(), 1);
        assert_eq!(toc.compression_methods, vec!["None"]);
    }

    #[test]
    fn ue4_27_export_bundle_is_not_misidentified_as_a_shader_chunk() {
        let mut data = fixture();
        data[16] = 3;
        data[52..56].copy_from_slice(&1u32.to_le_bytes());
        data[HEADER_SIZE + 11] = CHUNK_EXPORT_BUNDLE_UE427;
        data.drain(HEADER_SIZE + 24 + 20..HEADER_SIZE + 24 + 28);
        data[84..88].copy_from_slice(&0u32.to_le_bytes());
        data[96..100].copy_from_slice(&0u32.to_le_bytes());
        let toc = IoStoreToc::parse(&data).unwrap();
        assert_eq!(toc.shader_chunk_count(), 0);
        assert_eq!(toc.export_bundle_chunk_count(), 1);
        assert_eq!(toc.chunks[0].0.index, 1);
        assert_eq!(toc.partition_count, 1);
        assert_eq!(toc.partition_size, 0x10000);
    }

    #[test]
    fn parses_version_10_aes_ctr_ivs_before_compression_names() {
        let mut data = fixture();
        data[16] = 10;
        data[80] = 0x02; // Encrypted
        data[81] = ENCRYPTION_METHOD_AES_CTR;
        let iv_offset = HEADER_SIZE + 24 + 20 + 8 + 12;
        data.splice(iv_offset..iv_offset, [0x5au8; 12]);

        let toc = IoStoreToc::parse(&data).unwrap();
        assert_eq!(toc.encryption_method, ENCRYPTION_METHOD_AES_CTR);
        assert_eq!(toc.encryption_ivs, vec![[0x5a; 12]]);
        assert_eq!(toc.compression_methods, vec!["None"]);

        data.drain(iv_offset..iv_offset + 12);
        assert!(IoStoreToc::parse(&data).is_err());
    }

    #[test]
    fn rejects_truncated_or_non_iostore_data() {
        assert!(IoStoreToc::parse(b"not a toc").is_err());
        assert!(IoStoreToc::parse(&fixture()[..80]).is_err());
    }
}

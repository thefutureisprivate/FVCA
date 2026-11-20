//! Read single-profile x86-64 UKI policy from the Authenticode-covered sections.

use std::fs::File;
use std::io;

use object::read::{
    ReadCache, ReadRef,
    pe::{ImageNtHeaders, ImageOptionalHeader},
};
use object::{LittleEndian as LE, pe};

use crate::{Result, invalid};

const MAX_SECTIONS: usize = 96;
const MAX_CMDLINE: u64 = 32 * 1024;
const MAX_PCRSIG: u64 = 16 * 1024;

pub(super) struct Policy {
    pub cmdline: String,
    pub pcrsig: Option<String>,
}

pub(super) fn read(file: &File) -> Result<Policy> {
    let cache = ReadCache::new(file);
    parse(&cache, file.metadata()?.len())
}

fn parse<'a>(data: impl ReadRef<'a>, file_bytes: u64) -> Result<Policy> {
    let mut offset = u64::from(pe::ImageDosHeader::parse(data)?.nt_headers_offset());
    let (headers, directories) = pe::ImageNtHeaders64::parse(data, &mut offset)?;
    let optional = headers.optional_header();
    let count = usize::from(headers.file_header().number_of_sections.get(LE));
    if headers.file_header().machine.get(LE) != pe::IMAGE_FILE_MACHINE_AMD64
        || optional.subsystem() != pe::IMAGE_SUBSYSTEM_EFI_APPLICATION
        || !(1..=MAX_SECTIONS).contains(&count)
        || offset + (count * pe::IMAGE_SIZEOF_SECTION_HEADER) as u64
            > u64::from(optional.size_of_headers())
    {
        return Err(
            invalid("expected an x86-64 EFI application with a bounded section table").into(),
        );
    }
    let cert = directories
        .get(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)
        .ok_or_else(|| {
            invalid("the signed Hypervisor UKI has no Authenticode certificate table")
        })?;
    let cert_offset = u64::from(cert.virtual_address.get(LE));
    let cert_size = u64::from(cert.size.get(LE));
    let header_size = u64::from(optional.size_of_headers());
    if cert_offset < header_size
        || cert_size < 8
        || !cert_offset.is_multiple_of(8)
        || cert_offset + cert_size > file_bytes
    {
        return Err(invalid("invalid Hypervisor UKI Authenticode certificate extent").into());
    }

    let sections = headers.sections(data, offset)?;
    let mut raw = Vec::with_capacity(count);
    let mut virtual_ranges = Vec::with_capacity(count);
    let mut cmdline = None;
    let mut pcrsig = None;
    for section in sections.iter() {
        let start = u64::from(section.pointer_to_raw_data.get(LE));
        let bytes = u64::from(section.size_of_raw_data.get(LE));
        let size = u64::from(section.virtual_size.get(LE));
        if bytes != 0 {
            if start < header_size || start + bytes > cert_offset {
                return Err(invalid("UKI section extends outside the signed image data").into());
            }
            raw.push((start, start + bytes));
        }
        let address = u64::from(section.virtual_address.get(LE));
        if size != 0 {
            if address < header_size || address + size > u64::from(optional.size_of_image()) {
                return Err(invalid("UKI section extends outside the loaded image").into());
            }
            virtual_ranges.push((address, address + size));
        }
        let (field, limit) = match &section.name {
            b".cmdline" => (&mut cmdline, MAX_CMDLINE),
            b".pcrsig\0" => (&mut pcrsig, MAX_PCRSIG),
            b".profile" => return Err(invalid("expected a single-profile Hypervisor UKI").into()),
            _ => continue,
        };
        if field.is_some() || !(1..=limit.min(bytes)).contains(&size) {
            return Err(invalid("invalid or duplicate Hypervisor UKI policy section").into());
        }
        *field = Some(text(data, start, size)?);
    }
    require_disjoint(&mut raw)?;
    require_disjoint(&mut virtual_ranges)?;
    Ok(Policy {
        cmdline: cmdline.ok_or_else(|| invalid("missing signed Hypervisor UKI command line"))?,
        pcrsig,
    })
}

fn require_disjoint(extents: &mut [(u64, u64)]) -> io::Result<()> {
    extents.sort_unstable();
    if extents.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid("Hypervisor UKI sections overlap"));
    }
    Ok(())
}

fn text<'a>(data: impl ReadRef<'a>, offset: u64, size: u64) -> Result<String> {
    let bytes = data
        .read_bytes_at(offset, size)
        .map_err(|()| invalid("truncated UKI policy section"))?;
    let text = std::str::from_utf8(bytes)?.trim_end_matches('\0');
    if text.is_empty() || text.contains('\0') {
        return Err(invalid("invalid text in Hypervisor UKI policy section").into());
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NT: usize = 128;
    const OPT: usize = NT + 24;
    const SECTIONS: usize = OPT + 240;
    const HEADERS: usize = 1024;
    const RAW_SIZE: usize = 512;

    // Parser-only fixture. The installer tests use actual Authenticode-signed UKIs.
    fn image(sections: &[(&[u8; 8], &[u8])]) -> Vec<u8> {
        let certificate = HEADERS + sections.len() * RAW_SIZE;
        let mut bytes = vec![0; certificate + 8];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&(NT as u32).to_le_bytes());
        bytes[NT..NT + 4].copy_from_slice(b"PE\0\0");
        bytes[NT + 4..NT + 6].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[NT + 6..NT + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        bytes[NT + 20..NT + 22].copy_from_slice(&240_u16.to_le_bytes());
        bytes[OPT..OPT + 2].copy_from_slice(&0x020b_u16.to_le_bytes());
        bytes[OPT + 56..OPT + 60].copy_from_slice(&0x5000_u32.to_le_bytes());
        bytes[OPT + 60..OPT + 64].copy_from_slice(&(HEADERS as u32).to_le_bytes());
        bytes[OPT + 68..OPT + 70].copy_from_slice(&10_u16.to_le_bytes());
        bytes[OPT + 108..OPT + 112].copy_from_slice(&16_u32.to_le_bytes());
        // IMAGE_DIRECTORY_ENTRY_SECURITY stores a file offset, not an RVA.
        bytes[OPT + 144..OPT + 148].copy_from_slice(&(certificate as u32).to_le_bytes());
        bytes[OPT + 148..OPT + 152].copy_from_slice(&8_u32.to_le_bytes());
        for (index, (name, content)) in sections.iter().enumerate() {
            let offset = SECTIONS + index * pe::IMAGE_SIZEOF_SECTION_HEADER;
            let start = HEADERS + index * RAW_SIZE;
            bytes[offset..offset + 8].copy_from_slice(*name);
            for (slot, value) in [content.len(), 4096 * (index + 1), RAW_SIZE, start]
                .into_iter()
                .enumerate()
            {
                let position = offset + 8 + 4 * slot;
                bytes[position..position + 4].copy_from_slice(&(value as u32).to_le_bytes());
            }
            bytes[start..start + content.len()].copy_from_slice(content);
        }
        bytes
    }

    #[test]
    fn reads_only_declared_policy_bytes() -> Result<()> {
        let mut bytes = image(&[(b".cmdline", b"test\0"), (b".pcrsig\0", b"{\"sha256\":[]}")]);
        // A raw section has file-alignment padding outside its virtual size.
        bytes[HEADERS + 8] = 0xff;
        let policy = parse(bytes.as_slice(), bytes.len() as u64)?;
        assert_eq!(policy.cmdline, "test");
        assert_eq!(policy.pcrsig.as_deref(), Some("{\"sha256\":[]}"));
        Ok(())
    }

    #[test]
    fn rejects_ambiguous_or_unsigned_policy_bytes() {
        let primary = (b".cmdline", b"first".as_slice());
        for other in [b".cmdline", b".profile"] {
            let bytes = image(&[primary, (other, b"second")]);
            assert!(parse(bytes.as_slice(), bytes.len() as u64).is_err());
        }
        let bytes = image(&[primary, (b".pcrsig\0", b"zero\0hidden")]);
        assert!(parse(bytes.as_slice(), bytes.len() as u64).is_err());

        let mut bytes = image(&[primary]);
        let certificate = bytes.len() as u32 - 8;
        bytes[SECTIONS + 20..SECTIONS + 24].copy_from_slice(&certificate.to_le_bytes());
        assert!(parse(bytes.as_slice(), bytes.len() as u64).is_err());
    }
}

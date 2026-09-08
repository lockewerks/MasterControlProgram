//! # Static binary analysis
//!
//! Reading a PE off disk, without running it. The live debugger answers "what
//! is this process doing"; this answers "what is in this file", which is the
//! question you have first and the only one you have at all when running the
//! thing is a bad idea.
//!
//! Everything here is read-only and opens the file with shared access, so
//! inspecting a binary that is currently running or being written works instead
//! of failing on a sharing violation.
//!
//! Structure offsets are hardcoded rather than taken from the `windows` crate's
//! IMAGE_* types on purpose: those are memory layouts for a mapped image, and
//! this reads a file, where a header can be truncated, overlapping or lying.
//! Every field is bounds-checked against the real file length before it is
//! read, so a malformed PE produces an error naming the field and not a panic.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{bail, Context, Result};
use rmcp::{
    handler::server::wrapper::Parameters, model::CallToolResult, schemars, tool, tool_router,
    ErrorData as McpError,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::disasm::{self, Bitness};
use crate::server::MasterControlProgram;

/// Largest header region read in one go. A real PE header runs to a few
/// kilobytes; anything claiming more is malformed or hostile.
const MAX_HEADER_BYTES: usize = 1024 * 1024;

/// Ceiling on section, export and import entries reported. Well past what any
/// genuine binary carries, and it stops a corrupt count field from turning one
/// call into a gigabyte of JSON.
const MAX_ENTRIES: usize = 4096;

/// A PE opened for reading, with its headers parsed and validated.
struct Pe {
    file: File,
    length: u64,
    bitness: Bitness,
    machine: u16,
    image_base: u64,
    entry_point_rva: u32,
    subsystem: u16,
    characteristics: u16,
    dll_characteristics: u16,
    timestamp: u32,
    sections: Vec<Section>,
    directories: Vec<(u32, u32)>,
}

#[derive(Clone)]
struct Section {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

impl Section {
    fn executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    fn contains_rva(&self, rva: u32) -> bool {
        // The mapped size wins when it exceeds the raw size, which is the
        // normal case for a section with a .bss-style tail: those RVAs are
        // inside the section but have no bytes in the file.
        let size = self.virtual_size.max(self.raw_size);
        rva >= self.virtual_address && rva < self.virtual_address.saturating_add(size)
    }
}

fn word(bytes: &[u8], at: usize) -> Result<u16> {
    bytes
        .get(at..at + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
        .context("PE header field past end of header")
}

fn dword(bytes: &[u8], at: usize) -> Result<u32> {
    bytes
        .get(at..at + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        .context("PE header field past end of header")
}

fn qword(bytes: &[u8], at: usize) -> Result<u64> {
    bytes
        .get(at..at + 8)
        .map(|slice| {
            u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ])
        })
        .context("PE header field past end of header")
}

impl Pe {
    fn open(path: &str) -> Result<Self> {
        let path = Path::new(path);
        if !path.is_absolute() {
            bail!("binary path must be absolute");
        }
        let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let length = file
            .metadata()
            .context("cannot stat binary")?
            .len();
        if length < 64 {
            bail!("file is too small to be a PE image");
        }

        let mut dos = [0u8; 64];
        file.read_exact(&mut dos).context("cannot read DOS header")?;
        if &dos[..2] != b"MZ" {
            bail!("not a PE image: missing MZ signature");
        }
        let pe_offset = u64::from(dword(&dos, 0x3c)?);
        if pe_offset.saturating_add(248) > length {
            bail!("PE header offset 0x{pe_offset:x} lies past the end of the file");
        }

        // COFF header is 24 bytes, then the optional header. Read a generous
        // fixed window covering both plus every data directory.
        let header_size = 24 + 240;
        let header = read_at(&mut file, pe_offset, header_size)?;
        if &header[..4] != b"PE\0\0" {
            bail!("not a PE image: missing PE signature");
        }

        let machine = word(&header, 4)?;
        let bitness = Bitness::from_machine(machine)?;
        let section_count = word(&header, 6)? as usize;
        let timestamp = dword(&header, 8)?;
        let optional_size = word(&header, 20)? as usize;
        let characteristics = word(&header, 22)?;

        let magic = word(&header, 24)?;
        // The optional header's magic is authoritative for the field layout and
        // can disagree with the COFF machine in a hand-built file. Trusting the
        // machine word alone would read every subsequent field at the wrong
        // offset and report confident nonsense.
        let pe32_plus = match magic {
            0x10b => false,
            0x20b => true,
            other => bail!("unsupported optional header magic 0x{other:04x}"),
        };
        if pe32_plus != (bitness == Bitness::Bits64) {
            bail!("PE machine 0x{machine:04x} disagrees with optional header magic 0x{magic:04x}");
        }

        // Offsets below are from the start of the optional header, which sits
        // straight after the 24-byte COFF header. The two forms agree up to
        // ImageBase and diverge only in the width of five fields, so only the
        // directory count and the directory array need a branch.
        let optional = 24;
        let entry_point_rva = dword(&header, optional + 16)?;
        let image_base = if pe32_plus {
            qword(&header, optional + 24)?
        } else {
            u64::from(dword(&header, optional + 28)?)
        };
        let subsystem = word(&header, optional + 68)?;
        let dll_characteristics = word(&header, optional + 70)?;
        // SizeOfStackReserve through SizeOfHeapCommit are four fields, 8 bytes
        // each under PE32+ and 4 under PE32, which is the whole 16-byte gap.
        let count_at = if pe32_plus {
            optional + 108
        } else {
            optional + 92
        };
        let directory_count = dword(&header, count_at)? as usize;
        if directory_count > 16 {
            bail!("PE declares {directory_count} data directories, more than the 16 defined");
        }
        let mut directories = Vec::new();
        for index in 0..directory_count {
            let at = count_at + 4 + index * 8;
            directories.push((dword(&header, at)?, dword(&header, at + 4)?));
        }

        if section_count > MAX_ENTRIES {
            bail!("PE declares {section_count} sections, beyond the {MAX_ENTRIES} bound");
        }
        let table_offset = pe_offset + 24 + optional_size as u64;
        let table = read_at(&mut file, table_offset, section_count * 40)?;
        let mut sections = Vec::new();
        for index in 0..section_count {
            let at = index * 40;
            let raw_name = &table[at..at + 8];
            let end = raw_name.iter().position(|byte| *byte == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
                virtual_size: dword(&table, at + 8)?,
                virtual_address: dword(&table, at + 12)?,
                raw_size: dword(&table, at + 16)?,
                raw_offset: dword(&table, at + 20)?,
                characteristics: dword(&table, at + 36)?,
            });
        }

        Ok(Self {
            file,
            length,
            bitness,
            machine,
            image_base,
            entry_point_rva,
            subsystem,
            characteristics,
            dll_characteristics,
            timestamp,
            sections,
            directories,
        })
    }

    /// Translates an RVA to a file offset through the section table.
    ///
    /// Returns `None` for an RVA that is mapped but has no bytes on disk, which
    /// is a real and ordinary case: a section whose virtual size exceeds its
    /// raw size is zero-filled at load time, and there is nothing in the file
    /// to read. Reporting that honestly beats returning a plausible offset
    /// pointing at whatever follows in the file.
    fn offset_of(&self, rva: u32) -> Option<u64> {
        // An RVA below the first section is inside the headers, which are
        // mapped at their file offset.
        let first = self.sections.iter().map(|s| s.virtual_address).min();
        if first.is_some_and(|first| rva < first) {
            return Some(u64::from(rva));
        }
        let section = self.sections.iter().find(|s| s.contains_rva(rva))?;
        let delta = rva - section.virtual_address;
        if delta >= section.raw_size {
            return None;
        }
        Some(u64::from(section.raw_offset) + u64::from(delta))
    }

    fn section_of(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    fn read_rva(&mut self, rva: u32, length: usize) -> Result<Vec<u8>> {
        let offset = self
            .offset_of(rva)
            .with_context(|| format!("RVA 0x{rva:x} is not backed by bytes in the file"))?;
        // Clamped rather than refused: a window running off the end of the last
        // section is what asking for N instructions near the tail looks like,
        // and the decoder already reports a cut-off tail.
        let available = self.length.saturating_sub(offset) as usize;
        read_at(&mut self.file, offset, length.min(available))
    }

    /// A NUL-terminated ASCII name at an RVA, as export and import tables use.
    fn read_name(&mut self, rva: u32) -> Result<String> {
        let bytes = self.read_rva(rva, 256).unwrap_or_default();
        let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    fn exports(&mut self) -> Result<Value> {
        let Some(&(rva, size)) = self.directories.first() else {
            return Ok(json!({ "present": false }));
        };
        if rva == 0 || size == 0 {
            return Ok(json!({ "present": false }));
        }
        let table = self.read_rva(rva, 40)?;
        if table.len() < 40 {
            bail!("export directory is truncated");
        }
        let name_rva = dword(&table, 12)?;
        let ordinal_base = dword(&table, 16)?;
        let address_count = dword(&table, 20)? as usize;
        let name_count = dword(&table, 24)? as usize;
        let address_rva = dword(&table, 28)?;
        let names_rva = dword(&table, 32)?;
        let ordinals_rva = dword(&table, 36)?;

        if address_count > MAX_ENTRIES || name_count > MAX_ENTRIES {
            bail!("export table declares more than {MAX_ENTRIES} entries");
        }

        let module = if name_rva == 0 {
            None
        } else {
            Some(self.read_name(name_rva)?)
        };
        let addresses = self.read_rva(address_rva, address_count * 4).unwrap_or_default();
        let names = self.read_rva(names_rva, name_count * 4).unwrap_or_default();
        let ordinals = self.read_rva(ordinals_rva, name_count * 2).unwrap_or_default();

        let mut exports = Vec::new();
        for index in 0..name_count {
            if names.len() < (index + 1) * 4 || ordinals.len() < (index + 1) * 2 {
                break;
            }
            let name = self.read_name(dword(&names, index * 4)?)?;
            let ordinal = word(&ordinals, index * 2)? as usize;
            let function = if addresses.len() >= (ordinal + 1) * 4 {
                dword(&addresses, ordinal * 4)?
            } else {
                continue;
            };
            // An export whose address falls inside the export directory is a
            // forwarder: the "address" is really a "DLL.Function" string.
            let forwarded = function >= rva && function < rva.saturating_add(size);
            let mut entry = json!({
                "name": name,
                "ordinal": ordinal + ordinal_base as usize,
                "rva": format!("0x{function:x}"),
                "va": format!("0x{:x}", self.image_base + u64::from(function)),
            });
            if forwarded {
                entry["forwarded_to"] = json!(self.read_name(function)?);
                entry["rva"] = Value::Null;
                entry["va"] = Value::Null;
            }
            exports.push(entry);
        }

        Ok(json!({
            "present": true,
            "module_name": module,
            "named_count": name_count,
            "ordinal_count": address_count,
            "exports": exports,
        }))
    }

    fn imports(&mut self) -> Result<Value> {
        let Some(&(rva, _)) = self.directories.get(1) else {
            return Ok(json!({ "present": false }));
        };
        if rva == 0 {
            return Ok(json!({ "present": false }));
        }
        let pointer_size = if self.bitness == Bitness::Bits64 { 8 } else { 4 };
        let ordinal_flag = if self.bitness == Bitness::Bits64 {
            0x8000_0000_0000_0000u64
        } else {
            0x8000_0000u64
        };

        let mut modules = Vec::new();
        for index in 0..MAX_ENTRIES {
            let descriptor = self.read_rva(rva + (index as u32) * 20, 20)?;
            if descriptor.len() < 20 {
                break;
            }
            let lookup_rva = dword(&descriptor, 0)?;
            let name_rva = dword(&descriptor, 12)?;
            let address_rva = dword(&descriptor, 16)?;
            // The table ends at an all-zero descriptor.
            if name_rva == 0 && lookup_rva == 0 && address_rva == 0 {
                break;
            }
            let module = self.read_name(name_rva)?;

            // The lookup table survives binding; the address table is rewritten
            // in place by the loader. Prefer the former where it exists so a
            // bound import still reports names rather than addresses.
            let thunks_rva = if lookup_rva != 0 { lookup_rva } else { address_rva };
            let mut functions = Vec::new();
            for slot in 0..MAX_ENTRIES {
                let thunk = self
                    .read_rva(thunks_rva + (slot * pointer_size) as u32, pointer_size)
                    .unwrap_or_default();
                if thunk.len() < pointer_size {
                    break;
                }
                let value = if pointer_size == 8 {
                    qword(&thunk, 0)?
                } else {
                    u64::from(dword(&thunk, 0)?)
                };
                if value == 0 {
                    break;
                }
                if value & ordinal_flag != 0 {
                    functions.push(json!({ "ordinal": value & 0xffff, "name": null }));
                } else {
                    // The hint/name entry is a 2-byte hint then the name.
                    let name = self.read_name((value as u32).saturating_add(2))?;
                    functions.push(json!({ "name": name, "ordinal": null }));
                }
            }
            modules.push(json!({
                "module": module,
                "function_count": functions.len(),
                "functions": functions,
            }));
        }

        Ok(json!({ "present": true, "modules": modules }))
    }
}

fn read_at(file: &mut File, offset: u64, length: usize) -> Result<Vec<u8>> {
    if length > MAX_HEADER_BYTES.max(disasm::MAX_BYTES) {
        bail!("read length {length} exceeds bound");
    }
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("cannot seek to file offset 0x{offset:x}"))?;
    let mut bytes = vec![0u8; length];
    let mut filled = 0;
    while filled < length {
        match file.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) => return Err(error).context("cannot read binary"),
        }
    }
    bytes.truncate(filled);
    Ok(bytes)
}

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "native",
        2 => "windows_gui",
        3 => "windows_cui",
        5 => "os2_cui",
        7 => "posix_cui",
        9 => "windows_ce_gui",
        10 => "efi_application",
        11 => "efi_boot_service_driver",
        12 => "efi_runtime_driver",
        13 => "efi_rom",
        14 => "xbox",
        16 => "windows_boot_application",
        _ => "unknown",
    }
}

/// How the caller is naming a location in the file.
///
/// Three spellings of the same place, and mixing them up is the classic way to
/// disassemble the wrong bytes with total confidence. `Va` is what a debugger,
/// a crash dump or a map file quotes; `Rva` is what a PE header quotes; `File`
/// is what a hex editor quotes.
#[derive(Clone, Copy, Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Addressing {
    /// Virtual address, including the image base.
    #[default]
    Va,
    /// Relative virtual address, from the image base.
    Rva,
    /// Byte offset into the file on disk.
    File,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BinaryInspectInput {
    #[schemars(description = "Absolute path to a PE image (.exe, .dll, .sys).")]
    pub path: String,
    #[schemars(
        description = "Include the full import and export tables. Off by default, since a system DLL can carry thousands of entries."
    )]
    #[serde(default)]
    pub include_symbols: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BinaryDisassembleInput {
    #[schemars(description = "Absolute path to a PE image (.exe, .dll, .sys).")]
    pub path: String,
    #[schemars(
        description = "Location to disassemble from, interpreted per `addressing`. Omit to start at the image entry point."
    )]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub address: Option<u64>,
    #[serde(default)]
    pub addressing: Addressing,
    #[schemars(description = "Instructions to decode, 1-256, default 32.")]
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BinaryEncodeInput {
    #[schemars(
        description = "Address the patch will be written at. Relative branches are computed from it, so bytes encoded for one address are wrong at another."
    )]
    #[serde(deserialize_with = "crate::coerce::num")]
    pub address: u64,
    #[schemars(description = "Target architecture: x86 or x64.")]
    pub architecture: String,
    #[serde(flatten)]
    pub patch: disasm::Patch,
}

#[tool_router(router = binary_router, vis = "pub(crate)")]
impl MasterControlProgram {
    #[tool(
        description = "Read a PE image's headers, sections and optionally its import/export tables without running it. Reports machine, bitness, image base, entry point, subsystem and per-section addresses and characteristics."
    )]
    async fn binary_inspect(
        &self,
        Parameters(input): Parameters<BinaryInspectInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::diagnostics::response(inspect(input))
    }

    #[tool(
        description = "Disassemble x86/x64 instructions out of a PE image on disk, without running it. Address is a VA, RVA or file offset per `addressing`, and defaults to the entry point. Returns per-instruction address, bytes, masm text, flow control and resolved branch targets."
    )]
    async fn binary_disassemble(
        &self,
        Parameters(input): Parameters<BinaryDisassembleInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::diagnostics::response(disassemble_file(input))
    }

    #[tool(
        description = "Encode the bytes for a patch (nop run, ret, int3, jmp or call) at a specific address, and show what those bytes disassemble back to. Pure: writes nothing. Feed bytes_base64 to debug_memory_write, which applies them under its expected-bytes precondition."
    )]
    async fn binary_encode(
        &self,
        Parameters(input): Parameters<BinaryEncodeInput>,
    ) -> Result<CallToolResult, McpError> {
        crate::diagnostics::response(encode_patch(input))
    }
}

fn inspect(input: BinaryInspectInput) -> Result<Value> {
    let mut pe = Pe::open(&input.path)?;
    let sections: Vec<Value> = pe
        .sections
        .iter()
        .take(MAX_ENTRIES)
        .map(|section| {
            json!({
                "name": section.name,
                "rva": format!("0x{:x}", section.virtual_address),
                "va": format!("0x{:x}", pe.image_base + u64::from(section.virtual_address)),
                "virtual_size": section.virtual_size,
                "file_offset": format!("0x{:x}", section.raw_offset),
                "raw_size": section.raw_size,
                "characteristics": format!("0x{:08x}", section.characteristics),
                "readable": section.characteristics & 0x4000_0000 != 0,
                "writable": section.characteristics & 0x8000_0000 != 0,
                "executable": section.executable(),
            })
        })
        .collect();

    let entry_section = pe
        .section_of(pe.entry_point_rva)
        .map(|section| section.name.clone());

    let mut report = json!({
        "path": input.path,
        "file_size": pe.length,
        "machine": format!("0x{:04x}", pe.machine),
        "bitness": pe.bitness.bits(),
        "image_base": format!("0x{:x}", pe.image_base),
        "entry_point": {
            "rva": format!("0x{:x}", pe.entry_point_rva),
            "va": format!("0x{:x}", pe.image_base + u64::from(pe.entry_point_rva)),
            "section": entry_section,
        },
        "subsystem": subsystem_name(pe.subsystem),
        "timestamp": pe.timestamp,
        "is_dll": pe.characteristics & 0x2000 != 0,
        "aslr": pe.dll_characteristics & 0x0040 != 0,
        "nx": pe.dll_characteristics & 0x0100 != 0,
        "high_entropy_va": pe.dll_characteristics & 0x0020 != 0,
        "control_flow_guard": pe.dll_characteristics & 0x4000 != 0,
        "section_count": pe.sections.len(),
        "sections": sections,
    });

    if input.include_symbols {
        report["exports"] = pe.exports()?;
        report["imports"] = pe.imports()?;
    }
    Ok(report)
}

fn disassemble_file(input: BinaryDisassembleInput) -> Result<Value> {
    let mut pe = Pe::open(&input.path)?;
    let count = input.count.unwrap_or(32);
    if !(1..=disasm::MAX_INSTRUCTIONS).contains(&count) {
        bail!(
            "count must be between 1 and {}",
            disasm::MAX_INSTRUCTIONS
        );
    }

    // The entry point is the one place worth defaulting to: it is where you
    // start when you know nothing else about the file.
    let (rva, va) = match input.address {
        None => (
            pe.entry_point_rva,
            pe.image_base + u64::from(pe.entry_point_rva),
        ),
        Some(address) => match input.addressing {
            Addressing::Rva => {
                let rva = u32::try_from(address).context("RVA exceeds 32 bits")?;
                (rva, pe.image_base + address)
            }
            Addressing::Va => {
                let rva = address
                    .checked_sub(pe.image_base)
                    .with_context(|| {
                        format!(
                            "VA 0x{address:x} is below the image base 0x{:x}; pass addressing \"rva\" or \"file\" if that is not a virtual address",
                            pe.image_base
                        )
                    })?;
                (
                    u32::try_from(rva).context("VA is more than 4GB past the image base")?,
                    address,
                )
            }
            Addressing::File => {
                // Walk the section table backwards, from file offset to RVA.
                let section = pe
                    .sections
                    .iter()
                    .find(|section| {
                        address >= u64::from(section.raw_offset)
                            && address
                                < u64::from(section.raw_offset) + u64::from(section.raw_size)
                    })
                    .with_context(|| {
                        format!("file offset 0x{address:x} is not inside any section's raw data")
                    })?;
                let delta = (address - u64::from(section.raw_offset)) as u32;
                let rva = section.virtual_address + delta;
                (rva, pe.image_base + u64::from(rva))
            }
        },
    };

    let section = pe.section_of(rva).cloned();
    let bytes = pe.read_rva(rva, disasm::bytes_for(count))?;
    if bytes.is_empty() {
        bail!("RVA 0x{rva:x} has no bytes in the file; it is in a zero-filled section tail");
    }

    // Disassemble at the virtual address, not the RVA. Branch targets and
    // RIP-relative operands are then the addresses a debugger will show, which
    // is what makes a static read line up with a live one.
    let mut decoded = disasm::decode(&bytes, va, pe.bitness, count);
    decoded["rva"] = json!(format!("0x{rva:x}"));
    decoded["image_base"] = json!(format!("0x{:x}", pe.image_base));
    decoded["section"] = json!(section.as_ref().map(|section| section.name.clone()));
    // A caller who lands in .rdata gets instructions back, because bytes always
    // decode as something. Saying the section is not executable is the only
    // warning available without symbols.
    decoded["section_executable"] = json!(section.as_ref().map(Section::executable));
    Ok(decoded)
}

fn encode_patch(input: BinaryEncodeInput) -> Result<Value> {
    let bitness = Bitness::from_architecture(&input.architecture)?;
    let encoded = disasm::encode(&input.patch, input.address, bitness)?;
    Ok(serde_json::to_value(encoded)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every Windows box has these, they are stable, and reading them exercises
    /// the paths that matter: a 64-bit DLL with a large export table and a
    /// 64-bit EXE with imports.
    fn ntdll() -> String {
        r"C:\Windows\System32\ntdll.dll".to_string()
    }

    #[test]
    fn reads_a_real_system_dll() {
        let report = inspect(BinaryInspectInput {
            path: ntdll(),
            include_symbols: false,
        })
        .unwrap();
        assert_eq!(report["bitness"], 64);
        assert_eq!(report["is_dll"], true);
        // ntdll is subsystem 3 despite the name; "native" is smss and drivers.
        assert_eq!(report["subsystem"], "windows_cui");
        assert!(report["section_count"].as_u64().unwrap() > 1);
        let sections = report["sections"].as_array().unwrap();
        assert!(sections.iter().any(|section| section["name"] == ".text"
            && section["executable"] == true));
    }

    #[test]
    fn resolves_exports_and_imports() {
        let report = inspect(BinaryInspectInput {
            path: ntdll(),
            include_symbols: true,
        })
        .unwrap();
        assert_eq!(report["exports"]["present"], true);
        let exports = report["exports"]["exports"].as_array().unwrap();
        assert!(exports
            .iter()
            .any(|export| export["name"] == "NtCreateFile"));
    }

    #[test]
    fn disassembles_a_known_export() {
        let report = inspect(BinaryInspectInput {
            path: ntdll(),
            include_symbols: true,
        })
        .unwrap();
        let exports = report["exports"]["exports"].as_array().unwrap();
        let target = exports
            .iter()
            .find(|export| export["name"] == "NtCreateFile")
            .unwrap();
        let va = u64::from_str_radix(
            target["va"].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap();

        let decoded = disassemble_file(BinaryDisassembleInput {
            path: ntdll(),
            address: Some(va),
            addressing: Addressing::Va,
            count: Some(8),
        })
        .unwrap();
        assert_eq!(decoded["section"], ".text");
        assert_eq!(decoded["section_executable"], true);
        let instructions = decoded["instructions"].as_array().unwrap();
        assert!(!instructions.is_empty());
        // Every Nt* stub opens by stashing rcx in r10 for the syscall ABI.
        assert_eq!(instructions[0]["text"], "mov r10,rcx");
    }

    #[test]
    fn defaults_to_the_entry_point() {
        let decoded = disassemble_file(BinaryDisassembleInput {
            path: ntdll(),
            address: None,
            addressing: Addressing::Va,
            count: Some(4),
        })
        .unwrap();
        let report = inspect(BinaryInspectInput {
            path: ntdll(),
            include_symbols: false,
        })
        .unwrap();
        assert_eq!(decoded["address"], report["entry_point"]["va"]);
    }

    #[test]
    fn the_three_addressings_name_the_same_instruction() {
        let report = inspect(BinaryInspectInput {
            path: ntdll(),
            include_symbols: false,
        })
        .unwrap();
        let text = report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|section| section["name"] == ".text")
            .unwrap()
            .clone();
        let hex = |value: &Value| {
            u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };

        let by_va = disassemble_file(BinaryDisassembleInput {
            path: ntdll(),
            address: Some(hex(&text["va"])),
            addressing: Addressing::Va,
            count: Some(4),
        })
        .unwrap();
        let by_rva = disassemble_file(BinaryDisassembleInput {
            path: ntdll(),
            address: Some(hex(&text["rva"])),
            addressing: Addressing::Rva,
            count: Some(4),
        })
        .unwrap();
        let by_file = disassemble_file(BinaryDisassembleInput {
            path: ntdll(),
            address: Some(hex(&text["file_offset"])),
            addressing: Addressing::File,
            count: Some(4),
        })
        .unwrap();

        assert_eq!(by_va["instructions"], by_rva["instructions"]);
        assert_eq!(by_va["instructions"], by_file["instructions"]);
        assert_eq!(by_va["address"], by_rva["address"]);
        assert_eq!(by_va["address"], by_file["address"]);
    }

    #[test]
    fn refuses_a_va_below_the_image_base() {
        let error = disassemble_file(BinaryDisassembleInput {
            path: ntdll(),
            address: Some(0x1000),
            addressing: Addressing::Va,
            count: Some(4),
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("below the image base"));
    }

    #[test]
    fn refuses_a_relative_path_and_a_non_pe() {
        assert!(Pe::open("ntdll.dll").is_err());
        let error = Pe::open(r"C:\Windows\System32\drivers\etc\hosts")
            .err()
            .expect("a text file is not a PE");
        assert!(format!("{error:#}").contains("MZ") || format!("{error:#}").contains("too small"));
    }

    #[test]
    fn encodes_a_patch_through_the_tool_input() {
        let encoded = encode_patch(BinaryEncodeInput {
            address: 0x1000,
            architecture: "x64".to_string(),
            patch: disasm::Patch::Nop { length: 5 },
        })
        .unwrap();
        assert_eq!(encoded["bytes_hex"], "90 90 90 90 90");
        assert_eq!(encoded["encoded_for_address"], "0x1000");

        assert!(encode_patch(BinaryEncodeInput {
            address: 0x1000,
            architecture: "arm64".to_string(),
            patch: disasm::Patch::Int3,
        })
        .is_err());
    }
}

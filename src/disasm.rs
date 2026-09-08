//! # Disassembly, patch encoding, and static PE reading
//!
//! The decoder half of binary analysis. Everything here is pure: bytes in,
//! structured instructions out. Nothing in this module opens a process, reads
//! another program's memory, or writes anything. The live side calls [`decode`]
//! with bytes the debugger already read under its own bounds checks, and the
//! static side calls it with bytes mapped out of a file on disk.
//!
//! Patch bytes are produced here and written somewhere else on purpose.
//! `debug_memory_write` is the one audited path into another process's memory,
//! with its expected-bytes precondition and its breakpoint exclusion list.
//! Encoding a `jmp` is arithmetic; applying one is not, and duplicating the
//! guarded write to save a round trip would put a second door on the room.

use anyhow::{bail, Context, Result};
use iced_x86::{
    Code, Decoder, DecoderError, DecoderOptions, Encoder, FlowControl, Formatter, Instruction,
    MasmFormatter, OpKind,
};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Ceiling on instructions decoded in one call. A caller browsing a function
/// pages; a caller asking for the whole text section is asking for a file.
pub const MAX_INSTRUCTIONS: usize = 256;

/// Ceiling on bytes fed to the decoder in one call, matching the debugger's own
/// 65536-byte memory read bound so a live disassembly can never ask for a read
/// the memory path would refuse.
pub const MAX_BYTES: usize = 65536;

/// Longest encoding x86 admits. Used to size the read that backs a request for
/// N instructions, since their real length is not known until they are decoded.
const MAX_INSTRUCTION_LENGTH: usize = 15;

/// Decoder bitness. The debugger reports `x86` or `x64` and nothing else, and a
/// WOW64 target is `x86` while stopped in 32-bit code, so this maps one to one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bitness {
    Bits32,
    Bits64,
}

impl Bitness {
    pub fn bits(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }

    /// Maps the debugger's architecture string. Anything else is refused rather
    /// than guessed: decoding ARM64 bytes as x86 produces confident nonsense,
    /// which is worse than an error.
    pub fn from_architecture(architecture: &str) -> Result<Self> {
        match architecture {
            "x86" => Ok(Self::Bits32),
            "x64" => Ok(Self::Bits64),
            other => bail!("disassembly supports x86 and x64 targets, not {other}"),
        }
    }

    /// Maps a PE `IMAGE_FILE_HEADER.Machine` value.
    pub fn from_machine(machine: u16) -> Result<Self> {
        match machine {
            0x014c => Ok(Self::Bits32),
            0x8664 => Ok(Self::Bits64),
            0xaa64 => bail!("ARM64 image: disassembly supports x86 and x64 only"),
            other => bail!("unsupported PE machine 0x{other:04x}"),
        }
    }
}

/// How many bytes to read to be sure of decoding `count` instructions. Capped,
/// so the caller's bound survives contact with a long instruction stream.
pub fn bytes_for(count: usize) -> usize {
    count.saturating_mul(MAX_INSTRUCTION_LENGTH).min(MAX_BYTES)
}

/// Decodes up to `count` instructions from `bytes`, which are the memory or
/// file contents at `address`.
///
/// The final instruction is dropped when the buffer ends inside it: a truncated
/// tail decodes as whatever the missing bytes happen not to say, and reporting
/// that as an instruction is how a browse turns into a wrong answer. The
/// returned `next_address` is where a following page starts.
pub fn decode(bytes: &[u8], address: u64, bitness: Bitness, count: usize) -> Value {
    let count = count.min(MAX_INSTRUCTIONS);
    let mut decoder = Decoder::with_ip(bitness.bits(), bytes, address, DecoderOptions::NONE);
    let mut formatter = MasmFormatter::new();
    let mut instructions = Vec::new();
    let mut instruction = Instruction::default();
    let mut next = address;
    let mut truncated_tail = false;
    let mut invalid_at = None;

    while decoder.can_decode() && instructions.len() < count {
        let start = decoder.ip();
        decoder.decode_out(&mut instruction);

        // The decoder consumes the remaining bytes and hands back an invalid
        // instruction rather than overrunning the buffer, so the length is no
        // help here and the reason has to come off the decoder itself. The two
        // reasons are different answers: the caller's window ended mid
        // instruction, or the bytes are not code at all.
        if instruction.is_invalid() {
            match decoder.last_error() {
                DecoderError::NoMoreBytes => truncated_tail = true,
                _ => invalid_at = Some(format!("0x{start:x}")),
            }
            break;
        }

        let offset = (start - address) as usize;
        let end = offset + instruction.len();

        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        let encoded = &bytes[offset..end];

        let mut entry = json!({
            "address": format!("0x{start:x}"),
            "length": instruction.len(),
            "bytes": hex(encoded),
            "text": text,
            "mnemonic": format!("{:?}", instruction.mnemonic()).to_lowercase(),
            "flow_control": flow_control(instruction.flow_control()),
        });

        // A branch target is the one operand worth resolving for the caller:
        // it is what a browse follows, and the formatter prints it as a bare
        // number with no indication that it is an address at all.
        if let Some(target) = branch_target(&instruction) {
            entry["target"] = json!(format!("0x{target:x}"));
        }
        if instruction.is_ip_rel_memory_operand() {
            entry["memory_target"] =
                json!(format!("0x{:x}", instruction.ip_rel_memory_address()));
        }

        instructions.push(entry);
        next = decoder.ip();
    }

    json!({
        "address": format!("0x{address:x}"),
        "bitness": bitness.bits(),
        "instruction_count": instructions.len(),
        "instructions": instructions,
        "next_address": format!("0x{next:x}"),
        "decoded_bytes": next - address,
        // Distinguishes "you asked for 40 and the buffer held 12" from "the
        // 13th instruction was cut in half", which are different bugs upstream.
        "complete": instructions.len() == count,
        "truncated_tail": truncated_tail,
        // Set when the stream stopped being decodable code. Browsing off the
        // end of a function into a jump table or a string lands here, and
        // saying so is more use than emitting plausible garbage.
        "invalid_at": invalid_at,
    })
}

/// Branch and call targets that are known statically. Register and memory
/// indirect targets depend on runtime state this module cannot see, so they are
/// reported as absent rather than as zero.
fn branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instruction.near_branch_target())
        }
        _ => None,
    }
}

fn flow_control(flow: FlowControl) -> &'static str {
    match flow {
        FlowControl::Next => "next",
        FlowControl::UnconditionalBranch => "unconditional_branch",
        FlowControl::IndirectBranch => "indirect_branch",
        FlowControl::ConditionalBranch => "conditional_branch",
        FlowControl::Return => "return",
        FlowControl::Call => "call",
        FlowControl::IndirectCall => "indirect_call",
        FlowControl::Interrupt => "interrupt",
        FlowControl::XbeginXabortXend => "xbegin_xabort_xend",
        FlowControl::Exception => "exception",
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The patch shapes worth encoding for someone without source.
///
/// Deliberately a closed set. An arbitrary text assembler would be a parser
/// accepting anything, feeding a tool whose output goes into another process's
/// executable memory; these four cover neutralising a call, forcing a branch,
/// returning early and trapping, which is nearly all of what patching without
/// source actually is.
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Patch {
    /// `length` bytes of 0x90. Sized to the instructions being replaced, which
    /// the caller reads off a disassembly first.
    Nop {
        #[serde(deserialize_with = "crate::coerce::num")]
        length: usize,
    },
    /// A near return. `pop_bytes` emits `ret imm16` for a callee-cleanup
    /// convention, which 32-bit stdcall needs and 64-bit never does.
    Ret {
        #[serde(default, deserialize_with = "crate::coerce::opt_num")]
        pop_bytes: Option<u16>,
    },
    /// A one-byte 0xCC, for a breakpoint placed by hand rather than through the
    /// debugger's own tracked breakpoint table.
    Int3,
    /// An unconditional jump to `target`, encoded relative to `address`.
    Jump {
        #[serde(deserialize_with = "crate::coerce::num")]
        target: u64,
    },
    /// The same jump, as a call.
    Call {
        #[serde(deserialize_with = "crate::coerce::num")]
        target: u64,
    },
}

#[derive(Debug, Serialize)]
pub struct Encoded {
    pub address: String,
    pub length: usize,
    pub bytes_hex: String,
    pub bytes_base64: String,
    pub text: String,
    /// Repeated back so a caller pasting into `debug_memory_write` cannot
    /// silently pair these bytes with a different address than they were
    /// encoded for. A relative jump written one byte over goes somewhere else.
    pub encoded_for_address: String,
    pub bitness: u32,
}

/// Encodes one patch for a specific address.
///
/// The address matters for `Jump` and `Call` and is recorded for every kind,
/// because relative displacement is computed from it: the same five bytes
/// written one byte later land somewhere else entirely.
pub fn encode(patch: &Patch, address: u64, bitness: Bitness) -> Result<Encoded> {
    let bytes = match patch {
        Patch::Nop { length } => {
            if !(1..=4096).contains(length) {
                bail!("nop length must be between 1 and 4096 bytes");
            }
            vec![0x90u8; *length]
        }
        Patch::Int3 => vec![0xccu8],
        Patch::Ret { pop_bytes } => match pop_bytes {
            None | Some(0) => vec![0xc3u8],
            Some(pop) => {
                let mut bytes = vec![0xc2u8];
                bytes.extend_from_slice(&pop.to_le_bytes());
                bytes
            }
        },
        Patch::Jump { target } | Patch::Call { target } => {
            let call = matches!(patch, Patch::Call { .. });
            if bitness == Bitness::Bits32 && *target > u64::from(u32::MAX) {
                bail!("target 0x{target:x} does not fit a 32-bit address space");
            }
            let code = match (call, bitness) {
                (false, Bitness::Bits32) => Code::Jmp_rel32_32,
                (false, Bitness::Bits64) => Code::Jmp_rel32_64,
                (true, Bitness::Bits32) => Code::Call_rel32_32,
                (true, Bitness::Bits64) => Code::Call_rel32_64,
            };
            let instruction = Instruction::with_branch(code, *target)
                .context("branch target is not encodable")?;
            let mut encoder = Encoder::new(bitness.bits());
            // rel32 reaches +/-2GB. Beyond that the encoder refuses rather than
            // truncating the displacement, which would produce five plausible
            // bytes aimed at the wrong place.
            encoder.encode(&instruction, address).map_err(|error| {
                anyhow::anyhow!(
                    "cannot encode a relative branch from 0x{address:x} to 0x{target:x}: {error}"
                )
            })?;
            encoder.take_buffer()
        }
    };

    // Round-trip every encoding through the decoder and print what it actually
    // says. The caller is about to write this into executable memory, and the
    // text is the only part of the answer a person checks.
    let decoded = decode(&bytes, address, bitness, MAX_INSTRUCTIONS);
    let text = decoded["instructions"]
        .as_array()
        .map(|instructions| {
            instructions
                .iter()
                .filter_map(|instruction| instruction["text"].as_str())
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default();

    Ok(Encoded {
        address: format!("0x{address:x}"),
        length: bytes.len(),
        bytes_hex: hex(&bytes),
        bytes_base64: base64_encode(&bytes),
        text,
        encoded_for_address: format!("0x{address:x}"),
        bitness: bitness.bits(),
    })
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_x64_instructions_with_addresses() {
        // 48 89 e5       mov rbp, rsp
        // c3             ret
        let decoded = decode(&[0x48, 0x89, 0xe5, 0xc3], 0x1000, Bitness::Bits64, 16);
        let instructions = decoded["instructions"].as_array().unwrap();
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0]["address"], "0x1000");
        assert_eq!(instructions[0]["length"], 3);
        assert_eq!(instructions[1]["address"], "0x1003");
        assert_eq!(instructions[1]["flow_control"], "return");
        assert_eq!(decoded["next_address"], "0x1004");
    }

    #[test]
    fn drops_an_instruction_the_buffer_cuts_in_half() {
        // A five-byte call with only three bytes present. Decoding it would
        // invent the missing displacement.
        let decoded = decode(&[0x90, 0xe8, 0x01, 0x02], 0x2000, Bitness::Bits64, 16);
        let instructions = decoded["instructions"].as_array().unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0]["mnemonic"], "nop");
        assert_eq!(decoded["truncated_tail"], true);
        assert_eq!(decoded["next_address"], "0x2001");
    }

    #[test]
    fn reports_branch_targets_but_not_indirect_ones() {
        // eb 05  jmp +5, from 0x1000, lands at 0x1007
        let decoded = decode(&[0xeb, 0x05], 0x1000, Bitness::Bits64, 4);
        assert_eq!(decoded["instructions"][0]["target"], "0x1007");

        // ff e0  jmp rax, whose target is not knowable here
        let indirect = decode(&[0xff, 0xe0], 0x1000, Bitness::Bits64, 4);
        assert!(indirect["instructions"][0].get("target").is_none());
        assert_eq!(
            indirect["instructions"][0]["flow_control"],
            "indirect_branch"
        );
    }

    #[test]
    fn honors_the_instruction_count_bound() {
        let decoded = decode(&[0x90; 64], 0x1000, Bitness::Bits64, 4);
        assert_eq!(decoded["instruction_count"], 4);
        assert_eq!(decoded["complete"], true);
        assert_eq!(decoded["next_address"], "0x1004");
    }

    #[test]
    fn encodes_a_relative_jump_from_its_own_address() {
        let forward = encode(&Patch::Jump { target: 0x1100 }, 0x1000, Bitness::Bits64).unwrap();
        assert_eq!(forward.length, 5);
        assert_eq!(forward.text, "jmp near ptr 0000000000001100h");

        // The same target from a different address must encode differently, or
        // the displacement is not being computed from the address at all.
        let elsewhere = encode(&Patch::Jump { target: 0x1100 }, 0x1010, Bitness::Bits64).unwrap();
        assert_ne!(forward.bytes_hex, elsewhere.bytes_hex);
        assert_eq!(elsewhere.text, "jmp near ptr 0000000000001100h");
    }

    #[test]
    fn refuses_a_branch_past_the_reach_of_rel32() {
        let error = encode(
            &Patch::Jump {
                target: 0x7fff_ffff_0000,
            },
            0x1000,
            Bitness::Bits64,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("cannot encode a relative branch"));
    }

    #[test]
    fn encodes_the_simple_patch_shapes() {
        let nop = encode(&Patch::Nop { length: 3 }, 0x1000, Bitness::Bits64).unwrap();
        assert_eq!(nop.bytes_hex, "90 90 90");
        assert_eq!(nop.text, "nop; nop; nop");

        let ret = encode(&Patch::Ret { pop_bytes: None }, 0x1000, Bitness::Bits64).unwrap();
        assert_eq!(ret.bytes_hex, "c3");

        let stdcall = encode(
            &Patch::Ret {
                pop_bytes: Some(12),
            },
            0x1000,
            Bitness::Bits32,
        )
        .unwrap();
        assert_eq!(stdcall.bytes_hex, "c2 0c 00");

        let trap = encode(&Patch::Int3, 0x1000, Bitness::Bits64).unwrap();
        assert_eq!(trap.bytes_hex, "cc");
    }

    #[test]
    fn rejects_an_unreasonable_nop_run() {
        assert!(encode(&Patch::Nop { length: 0 }, 0x1000, Bitness::Bits64).is_err());
        assert!(encode(&Patch::Nop { length: 4097 }, 0x1000, Bitness::Bits64).is_err());
    }

    #[test]
    fn refuses_an_architecture_it_cannot_decode() {
        assert!(Bitness::from_architecture("arm64").is_err());
        assert!(Bitness::from_machine(0xaa64).is_err());
        assert_eq!(
            Bitness::from_architecture("x64").unwrap(),
            Bitness::Bits64
        );
        assert_eq!(Bitness::from_machine(0x014c).unwrap(), Bitness::Bits32);
    }

    #[test]
    fn thirty_two_bit_decoding_differs_from_sixty_four() {
        // 0x48 is a REX prefix in long mode and `dec eax` in 32-bit.
        let long = decode(&[0x48, 0x89, 0xe5], 0x1000, Bitness::Bits64, 4);
        let protected = decode(&[0x48, 0x89, 0xe5], 0x1000, Bitness::Bits32, 4);
        assert_eq!(long["instruction_count"], 1);
        assert_eq!(protected["instruction_count"], 2);
        assert_eq!(protected["instructions"][0]["mnemonic"], "dec");
    }
}

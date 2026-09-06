//! # Filesystem Operations: FindFirstFileW and the Audacity of 1995
//!
//! Welcome to the Windows filesystem API, where we enumerate files using
//! FindFirstFileW/FindNextFileW, an iterator pattern from Windows 95 that
//! Microsoft never replaced because "if it ain't broke, don't fix it" is
//! their entire philosophy (even when it IS broke).
//!
//! Timestamps are FILETIME structs: 64-bit values counting 100-nanosecond
//! intervals since January 1, 1601. Why 1601? Because that's the start of a
//! 400-year Gregorian calendar cycle. Someone at Microsoft in 1989 thought this
//! was a reasonable epoch and NOBODY STOPPED THEM.
//!
//! File attributes are a bitmask because of course they are. Want to know if
//! something is a directory? Bitwise AND with FILE_ATTRIBUTE_DIRECTORY. Hidden?
//! Another bitmask. Read-only? You guessed it. It's like a punch card but worse.
//!
//! And to get the owner of a file you need GetNamedSecurityInfoW (returns a SID)
//! then LookupAccountSidW (turns the SID into a name). TWO API calls to answer
//! "who owns this file?" Other operating systems call this `stat()`.

use super::{pretty, to_wide, wchar_to_string};
use anyhow::{bail, ensure, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::Cryptography::{BCryptHash, BCRYPT_SHA256_ALG_HANDLE};
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::SystemServices::{
    IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK, MAXIMUM_ALLOWED,
};

const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_BATCH: usize = 32;
const MAX_BATCH_BYTES: usize = 32 * 1024 * 1024;
const MAX_PATH_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Base64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WriteBom {
    #[default]
    Preserve,
    Add,
    Remove,
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum FileConsistency {
    CreateNew,
    AtomicReplace,
    #[default]
    ConditionalInPlace,
    Transactional,
}

#[derive(Clone, Copy, Debug, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WriteMetadata {
    Preserve,
    DestinationDefaults,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FsReadInput {
    pub path: String,
    /// Explicit encoding. Text BOMs are validated and stripped; base64 returns exact bytes.
    pub encoding: FileEncoding,
    /// Reject larger files instead of returning truncated data. Default 1 MiB, maximum 8 MiB.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_bytes: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FsWriteInput {
    pub path: String,
    pub data: String,
    pub encoding: FileEncoding,
    /// Atomic replacement is unconditional and creates a new file object. Conditional writes preserve the existing object.
    pub consistency: FileConsistency,
    /// AtomicReplace requires destination_defaults explicitly. Conditional modes require preserve (the default).
    pub metadata: Option<WriteMetadata>,
    #[serde(default)]
    pub bom: WriteBom,
    /// Required for conditional_in_place and transactional; forbidden for create_new and atomic_replace.
    pub expected_revision: Option<String>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FsPatchInput {
    pub path: String,
    pub encoding: FileEncoding,
    pub expected_revision: String,
    /// conditional_in_place (default), or explicit transactional mode on a supported NTFS volume.
    #[serde(default)]
    pub consistency: FileConsistency,
    pub find: String,
    pub replacement: String,
    /// Exact number of non-overlapping literal matches required, between 1 and 10000.
    #[serde(deserialize_with = "crate::coerce::num")]
    pub expected_matches: u32,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u32>,
}

#[derive(Clone, Copy, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CopySecurity {
    /// Copy the source owner/group/DACL and protect it from destination inheritance. SACL uses destination defaults.
    Source,
    DestinationDefaults,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileTransfer {
    pub source: String,
    pub destination: String,
    pub expected_revision: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FsCopyInput {
    /// Each destination must be absent. Directories, reparse points and alternate streams are rejected.
    pub files: Vec<FileTransfer>,
    /// Explicitly choose source owner/DACL or the destination directory's defaults.
    pub security: CopySecurity,
    #[serde(default)]
    pub continue_on_error: bool,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FsMoveInput {
    /// Same-volume file renames only, each destination must be absent.
    pub files: Vec<FileTransfer>,
    #[serde(default)]
    pub continue_on_error: bool,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Hard,
    SymbolicFile,
    SymbolicDirectory,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FsLinkCreateInput {
    pub path: String,
    pub target: String,
    pub kind: LinkKind,
    /// Required for hard links, using the exact target revision returned by fs_read.
    pub expected_target_revision: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FsLinkRemoveInput {
    pub path: String,
    pub expected_revision: String,
}

#[derive(Clone, Copy, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    #[serde(rename = "self")]
    SelfOnly,
    Children,
    Recursive,
}

#[derive(Clone, Copy, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaclInheritance {
    Preserve,
    ProtectCopy,
    ProtectRemove,
    Enable,
}

#[derive(Clone, Copy, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AclEdit {
    Merge,
    Replace,
}

#[derive(Clone, Copy, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AceMode {
    Grant,
    Set,
    Deny,
    Revoke,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AclEntry {
    /// Exact Windows SID, not an ambiguous account display name.
    pub sid: String,
    pub mode: AceMode,
    /// Windows file access mask. Revoke requires zero.
    #[serde(deserialize_with = "crate::coerce::num")]
    pub rights: u32,
    /// OI=1, CI=2, NP=4, IO=8. Inherited and audit flags cannot be supplied.
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub inheritance_flags: Option<u8>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FsAclInput {
    pub path: String,
    pub scope: TargetScope,
    pub inheritance: DaclInheritance,
    /// Replace with an empty list deliberately creates an empty (deny-all), never a null DACL.
    pub mode: AclEdit,
    pub entries: Vec<AclEntry>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_depth: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_targets: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FsOwnerInput {
    pub path: String,
    pub scope: TargetScope,
    pub owner_sid: String,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_depth: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub max_targets: Option<u32>,
    #[serde(default, deserialize_with = "crate::coerce::opt_num")]
    pub timeout_ms: Option<u32>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct SidIdentity {
    pub sid: String,
    pub account: Option<String>,
    pub account_lookup_error: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct AclAce {
    pub ace_type: u8,
    pub flags: u8,
    pub rights: Option<u32>,
    pub trustee: Option<SidIdentity>,
    pub raw_base64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume_serial: String,
    pub file_id: String,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct FileReadResult {
    pub path: String,
    pub identity: FileIdentity,
    pub revision: String,
    pub encoding: FileEncoding,
    pub bom: bool,
    pub bytes: usize,
    pub data: String,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct FileMutationResult {
    pub path: String,
    pub consistency: FileConsistency,
    pub precondition: String,
    pub atomicity: String,
    pub metadata: String,
    pub accepted: bool,
    pub bytes_written: usize,
    pub identity: Option<FileIdentity>,
    pub revision: Option<String>,
    pub outcome: String,
    pub error: Option<String>,
}

struct Budget {
    end: Instant,
    timeout_ms: u32,
}

impl Budget {
    fn new(timeout_ms: Option<u32>) -> anyhow::Result<Self> {
        let timeout_ms = timeout_ms.unwrap_or(30_000);
        ensure!(
            (1..=120_000).contains(&timeout_ms),
            "timeout_ms must be 1..120000"
        );
        Ok(Self {
            end: Instant::now() + Duration::from_millis(timeout_ms.into()),
            timeout_ms,
        })
    }

    fn check(&self) -> anyhow::Result<()> {
        crate::runtime::checkpoint()?;
        ensure!(Instant::now() < self.end, "operation deadline exceeded");
        Ok(())
    }
}

fn handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

fn win32_result(code: WIN32_ERROR) -> anyhow::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(windows::core::Error::from_hresult(code.to_hresult()).into())
    }
}

fn check_string(value: &str, name: &str) -> anyhow::Result<()> {
    ensure!(
        !value.is_empty() && !value.contains('\0'),
        "{name} must be nonempty and contain no NUL"
    );
    ensure!(value.encode_utf16().count() <= 32_000, "{name} is too long");
    Ok(())
}

fn file_path(value: &str) -> anyhow::Result<PathBuf> {
    check_string(value, "path")?;
    let path = PathBuf::from(value);
    ensure!(
        path.is_absolute(),
        "an absolute filesystem path is required"
    );
    ensure!(
        matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_) | Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _))),
        "device namespaces and non-filesystem paths are unsupported"
    );
    let mut depth = 0;
    for part in path.components() {
        match part {
            Component::Normal(part) => {
                let part = part.to_str().context("path is not valid Unicode")?;
                ensure!(
                    !part.contains([':', '*', '?']) && !part.ends_with(['.', ' ']),
                    "alternate streams, wildcards and ambiguous path components are unsupported"
                );
                depth += 1;
            }
            Component::ParentDir | Component::CurDir => {
                bail!("path must not contain '.' or '..' components")
            }
            _ => {}
        }
    }
    ensure!(
        depth <= MAX_PATH_DEPTH,
        "path exceeds {MAX_PATH_DEPTH} components"
    );
    Ok(path)
}

fn path_string(path: &Path) -> anyhow::Result<&str> {
    path.to_str().context("path is not valid Unicode")
}

fn open_path(
    path: &Path,
    access: u32,
    share: FILE_SHARE_MODE,
    transaction: Option<HANDLE>,
) -> anyhow::Result<File> {
    let wide = to_wide(path_string(path)?);
    let flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
    let native = unsafe {
        if let Some(transaction) = transaction {
            CreateFileTransactedW(
                PCWSTR(wide.as_ptr()),
                access,
                share,
                None,
                OPEN_EXISTING,
                flags,
                None,
                transaction,
                None,
                None,
            )
        } else {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                access,
                share,
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        }
    }
    .with_context(|| format!("open {}", path.display()))?;
    Ok(unsafe { File::from_raw_handle(native.0) })
}

fn file_info<T: Default>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> anyhow::Result<T> {
    let mut info = T::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle(file),
            class,
            &mut info as *mut T as *mut _,
            std::mem::size_of::<T>() as u32,
        )?;
    }
    Ok(info)
}

fn basic_info(file: &File) -> anyhow::Result<FILE_BASIC_INFO> {
    file_info(file, FileBasicInfo)
}

fn identity(file: &File) -> anyhow::Result<FileIdentity> {
    let info: FILE_ID_INFO = file_info(file, FileIdInfo)?;
    Ok(FileIdentity {
        volume_serial: format!("{:016x}", info.VolumeSerialNumber),
        file_id: hex(&info.FileId.Identifier),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(bytes: &[u8]) -> anyhow::Result<String> {
    let mut output = [0; 32];
    unsafe {
        BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, bytes, &mut output).ok()?;
    }
    Ok(hex(&output))
}

fn reject_reparse(file: &File) -> anyhow::Result<()> {
    let info: FILE_ATTRIBUTE_TAG_INFO = file_info(file, FileAttributeTagInfo)?;
    ensure!(
        info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
        "reparse points are not followed; use an explicit target path or link tools"
    );
    Ok(())
}

struct PinnedPath {
    path: PathBuf,
    _parents: Vec<File>,
}

impl PinnedPath {
    fn new(value: &str, budget: &Budget) -> anyhow::Result<Self> {
        let path = file_path(value)?;
        let mut ancestors: Vec<_> = path.ancestors().skip(1).filter(|p| p.has_root()).collect();
        ancestors.reverse();
        let mut parents = Vec::new();
        for ancestor in ancestors {
            budget.check()?;
            // Pin each ancestor before opening its child, including against reparse-point writes.
            let file = open_path(ancestor, FILE_READ_ATTRIBUTES.0, FILE_SHARE_READ, None)?;
            reject_reparse(&file)?;
            ensure!(
                basic_info(&file)?.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
                "ancestor is not a directory"
            );
            parents.push(file);
        }
        Ok(Self {
            path,
            _parents: parents,
        })
    }

    fn open(&self, access: u32, transaction: Option<HANDLE>) -> anyhow::Result<File> {
        open_path(&self.path, access, FILE_SHARE_READ, transaction)
    }
}

struct Snapshot {
    identity: FileIdentity,
    revision: String,
    basic: FILE_BASIC_INFO,
    data: Vec<u8>,
}

fn snapshot(file: &mut File, limit: usize, budget: &Budget) -> anyhow::Result<Snapshot> {
    budget.check()?;
    reject_reparse(file)?;
    let before = basic_info(file)?;
    ensure!(
        before.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0,
        "directories are unsupported for file content operations"
    );
    let size: FILE_STANDARD_INFO = file_info(file, FileStandardInfo)?;
    let length = usize::try_from(size.EndOfFile).context("invalid or overflowing file length")?;
    ensure!(
        length <= limit && length <= MAX_FILE_BYTES,
        "file exceeds the {limit} byte limit"
    );
    let identity = identity(file)?;
    let mut data = vec![0; length];
    file.seek(SeekFrom::Start(0))?;
    for block in data.chunks_mut(64 * 1024) {
        budget.check()?;
        file.read_exact(block)
            .context("file changed or could not be read completely")?;
    }
    let after = basic_info(file)?;
    let after_size: FILE_STANDARD_INFO = file_info(file, FileStandardInfo)?;
    ensure!(
        before.LastWriteTime == after.LastWriteTime
            && before.ChangeTime == after.ChangeTime
            && size.EndOfFile == after_size.EndOfFile,
        "revision conflict: file changed during read"
    );
    let revision = format!(
        "fs1:{}:{}:{:x}:{:x}:{:x}:{:x}:{:x}:{}",
        identity.volume_serial,
        identity.file_id,
        before.CreationTime,
        before.LastWriteTime,
        before.ChangeTime,
        length,
        before.FileAttributes,
        digest(&data)?
    );
    Ok(Snapshot {
        identity,
        revision,
        basic: before,
        data,
    })
}

fn check_revision(actual: &str, expected: &str) -> anyhow::Result<()> {
    ensure!(
        expected.len() <= 512 && expected == actual,
        "revision conflict: target identity or contents changed; read the file again"
    );
    Ok(())
}

fn decode(data: &[u8], encoding: FileEncoding) -> anyhow::Result<(String, bool)> {
    if encoding == FileEncoding::Base64 {
        return Ok((STANDARD.encode(data), false));
    }
    let marker = match encoding {
        FileEncoding::Utf8 => b"\xef\xbb\xbf".as_slice(),
        FileEncoding::Utf16Le => b"\xff\xfe".as_slice(),
        FileEncoding::Utf16Be => b"\xfe\xff".as_slice(),
        FileEncoding::Base64 => unreachable!(),
    };
    let bom = data.starts_with(marker);
    ensure!(
        bom || ![
            b"\xef\xbb\xbf".as_slice(),
            b"\xff\xfe".as_slice(),
            b"\xfe\xff".as_slice()
        ]
        .iter()
        .any(|prefix| data.starts_with(prefix)),
        "BOM does not match the requested encoding"
    );
    let data = if bom { &data[marker.len()..] } else { data };
    let text = match encoding {
        FileEncoding::Utf8 => std::str::from_utf8(data)
            .context("invalid UTF-8")?
            .to_owned(),
        FileEncoding::Utf16Le | FileEncoding::Utf16Be => {
            ensure!(data.len() % 2 == 0, "UTF-16 has an odd byte length");
            let units: Vec<u16> = data
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| {
                    if encoding == FileEncoding::Utf16Le {
                        u16::from_le_bytes([p[0], p[1]])
                    } else {
                        u16::from_be_bytes([p[0], p[1]])
                    }
                })
                .collect();
            String::from_utf16(&units).context("invalid UTF-16")?
        }
        FileEncoding::Base64 => unreachable!(),
    };
    Ok((text, bom))
}

fn encode(
    text: &str,
    encoding: FileEncoding,
    bom: WriteBom,
    previous: bool,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        text.len() <= MAX_FILE_BYTES * 2,
        "input exceeds the size limit"
    );
    if encoding == FileEncoding::Base64 {
        ensure!(
            matches!(bom, WriteBom::Preserve),
            "BOM options do not apply to base64; bytes are used verbatim"
        );
        let data = STANDARD.decode(text).context("invalid base64")?;
        ensure!(
            data.len() <= MAX_FILE_BYTES,
            "decoded bytes exceed the size limit"
        );
        return Ok(data);
    }
    let add_bom = matches!(bom, WriteBom::Add) || matches!(bom, WriteBom::Preserve) && previous;
    let mut data = Vec::new();
    if add_bom {
        data.extend_from_slice(match encoding {
            FileEncoding::Utf8 => b"\xef\xbb\xbf",
            FileEncoding::Utf16Le => b"\xff\xfe",
            FileEncoding::Utf16Be => b"\xfe\xff",
            FileEncoding::Base64 => unreachable!(),
        });
    }
    match encoding {
        FileEncoding::Utf8 => data.extend_from_slice(text.as_bytes()),
        FileEncoding::Utf16Le | FileEncoding::Utf16Be => {
            for unit in text.encode_utf16() {
                data.extend_from_slice(&if encoding == FileEncoding::Utf16Le {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
        }
        FileEncoding::Base64 => unreachable!(),
    }
    ensure!(
        data.len() <= MAX_FILE_BYTES,
        "encoded bytes exceed the size limit"
    );
    Ok(data)
}

pub fn read(input: FsReadInput) -> anyhow::Result<String> {
    let limit = input.max_bytes.unwrap_or(1024 * 1024) as usize;
    ensure!(
        (1..=MAX_FILE_BYTES).contains(&limit),
        "max_bytes must be 1..{MAX_FILE_BYTES}"
    );
    let budget = Budget::new(input.timeout_ms)?;
    let path = PinnedPath::new(&input.path, &budget)?;
    let mut file = path.open(GENERIC_READ.0, None)?;
    let snap = snapshot(&mut file, limit, &budget)?;
    let (data, bom) = decode(&snap.data, input.encoding)?;
    Ok(serde_json::to_string_pretty(&FileReadResult {
        path: input.path,
        identity: snap.identity,
        revision: snap.revision,
        encoding: input.encoding,
        bom,
        bytes: snap.data.len(),
        data,
    })?)
}

struct Transaction {
    handle: HANDLE,
    finished: bool,
}

impl Transaction {
    fn new(budget: &Budget) -> anyhow::Result<Self> {
        budget.check()?;
        let handle = unsafe {
            CreateTransaction(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,
                0,
                budget.timeout_ms,
                None,
            )?
        };
        Ok(Self {
            handle,
            finished: false,
        })
    }

    fn commit(&mut self) -> anyhow::Result<()> {
        unsafe {
            CommitTransaction(self.handle)?;
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        unsafe {
            if !self.finished {
                if let Err(error) = RollbackTransaction(self.handle) {
                    tracing::error!(%error, "filesystem transaction rollback failed");
                }
            }
            if let Err(error) = CloseHandle(self.handle) {
                tracing::error!(%error, "filesystem transaction handle close failed");
            }
        }
    }
}

struct TemporaryFile {
    file: File,
    path: PathBuf,
    published: bool,
}

impl TemporaryFile {
    fn new(destination: &PinnedPath) -> anyhow::Result<Self> {
        let parent = destination
            .path
            .parent()
            .context("a destination file name is required")?;
        let path = parent.join(format!(".mcp-{}.tmp", uuid::Uuid::new_v4()));
        let wide = to_wide(path_string(&path)?);
        let native = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0 | DELETE.0 | WRITE_DAC.0 | WRITE_OWNER.0,
                FILE_SHARE_READ,
                None,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };
        Ok(Self {
            file: unsafe { File::from_raw_handle(native.0) },
            path,
            published: false,
        })
    }

    fn publish(&mut self, destination: &PinnedPath, replace: bool) -> anyhow::Result<()> {
        rename_handle(&self.file, &destination.path, replace)?;
        self.published = true;
        Ok(())
    }

    fn cleanup(&mut self) -> anyhow::Result<()> {
        if !self.published {
            let mut basic = basic_info(&self.file)?;
            if basic.FileAttributes & FILE_ATTRIBUTE_READONLY.0 != 0 {
                basic.FileAttributes &= !FILE_ATTRIBUTE_READONLY.0;
                if basic.FileAttributes == 0 {
                    // Zero preserves attributes; NORMAL clears the final read-only bit.
                    basic.FileAttributes = FILE_ATTRIBUTE_NORMAL.0;
                }
                unsafe {
                    SetFileInformationByHandle(
                        handle(&self.file),
                        FileBasicInfo,
                        &basic as *const _ as *const _,
                        std::mem::size_of_val(&basic) as u32,
                    )?;
                }
            }
            disposition(&self.file)?;
            self.published = true;
        }
        Ok(())
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::error!(%error, path = %self.path.display(), "temporary file cleanup failed");
        }
    }
}

fn disposition(file: &File) -> anyhow::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            handle(file),
            FileDispositionInfo,
            &info as *const _ as *const _,
            std::mem::size_of_val(&info) as u32,
        )?;
    }
    Ok(())
}

fn rename_handle(file: &File, destination: &Path, replace: bool) -> anyhow::Result<()> {
    let name: Vec<u16> = path_string(destination)?.encode_utf16().collect();
    let size = std::mem::offset_of!(FILE_RENAME_INFO, FileName) + name.len() * 2;
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = HANDLE::default();
        (*info).FileNameLength = u32::try_from(name.len() * 2)?;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        SetFileInformationByHandle(
            handle(file),
            FileRenameInfo,
            info.cast(),
            u32::try_from(size)?,
        )?;
    }
    Ok(())
}

#[derive(Default)]
struct WriteProgress {
    bytes: usize,
    accepted: bool,
}

fn write_contents(
    file: &mut File,
    data: &[u8],
    budget: &Budget,
    written: &mut WriteProgress,
) -> anyhow::Result<()> {
    budget.check()?;
    file.seek(SeekFrom::Start(0))?;
    write_chunks(file, data, budget, written)?;
    budget.check()?;
    file.set_len(data.len() as u64)?;
    written.accepted = true;
    file.sync_all()?;
    Ok(())
}

fn write_chunks<W: Write>(
    file: &mut W,
    data: &[u8],
    budget: &Budget,
    written: &mut WriteProgress,
) -> anyhow::Result<()> {
    for block in data.chunks(64 * 1024) {
        let mut remaining = block;
        while !remaining.is_empty() {
            budget.check()?;
            let count = file.write(remaining)?;
            ensure!(count != 0, "file write returned zero bytes");
            written.bytes += count;
            written.accepted = true;
            remaining = &remaining[count..];
        }
    }
    Ok(())
}

fn preserve_write_metadata(file: &File, original: FILE_BASIC_INFO) -> anyhow::Result<()> {
    let basic = FILE_BASIC_INFO {
        CreationTime: original.CreationTime,
        LastAccessTime: original.LastAccessTime,
        FileAttributes: original.FileAttributes,
        ..Default::default()
    };
    unsafe {
        SetFileInformationByHandle(
            handle(file),
            FileBasicInfo,
            &basic as *const _ as *const _,
            std::mem::size_of_val(&basic) as u32,
        )?;
    }
    file.sync_all()?;
    Ok(())
}

fn observe_written(
    path: &PinnedPath,
    expected_id: &FileIdentity,
    data: &[u8],
    budget: &Budget,
) -> anyhow::Result<String> {
    let mut file = path.open(GENERIC_READ.0, None)?;
    let observed = snapshot(&mut file, MAX_FILE_BYTES, budget)?;
    ensure!(
        observed.identity == *expected_id && observed.data == data,
        "write was accepted, but the path changed again before observation"
    );
    Ok(observed.revision)
}

fn mutation_result(
    path: &str,
    consistency: FileConsistency,
    accepted: bool,
    bytes_written: usize,
    id: Option<FileIdentity>,
    revision: Option<String>,
    error: Option<String>,
) -> String {
    let (precondition, atomicity, metadata) = match consistency {
        FileConsistency::CreateNew => (
            "must_not_exist",
            "atomic_namespace_publication",
            "destination_defaults",
        ),
        FileConsistency::AtomicReplace => (
            "unconditional_path",
            "atomic_namespace_replacement",
            "destination_defaults",
        ),
        FileConsistency::ConditionalInPlace => {
            ("exact_revision", "in_place_not_crash_atomic", "preserved")
        }
        FileConsistency::Transactional => {
            ("exact_revision", "explicit_ntfs_transaction", "preserved")
        }
    };
    let outcome = if error.is_none() {
        "completed"
    } else if accepted || bytes_written != 0 {
        "partial_or_unobserved"
    } else {
        "failed"
    };
    pretty(&json!(FileMutationResult {
        path: path.to_owned(),
        consistency,
        precondition: precondition.to_owned(),
        atomicity: atomicity.to_owned(),
        metadata: metadata.to_owned(),
        accepted,
        bytes_written,
        identity: id,
        revision,
        outcome: outcome.to_owned(),
        error,
    }))
}

fn publish_data(
    path: &PinnedPath,
    data: &[u8],
    consistency: FileConsistency,
    budget: &Budget,
) -> anyhow::Result<String> {
    let mut temporary = TemporaryFile::new(path)?;
    let id = identity(&temporary.file)?;
    let mut written = WriteProgress::default();
    let preparation = write_contents(&mut temporary.file, data, budget, &mut written)
        .and_then(|()| budget.check())
        .and_then(|()| temporary.publish(path, consistency == FileConsistency::AtomicReplace));
    if let Err(error) = preparation {
        let cleanup = temporary.cleanup();
        return Err(match cleanup {
            Ok(()) => error,
            Err(cleanup) => error.context(format!(
                "temporary cleanup also failed for {}: {cleanup:#}",
                temporary.path.display()
            )),
        });
    }
    drop(temporary);
    let observed = observe_written(path, &id, data, budget);
    let (revision, error) = match observed {
        Ok(revision) => (Some(revision), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    Ok(mutation_result(
        path_string(&path.path)?,
        consistency,
        true,
        written.bytes,
        Some(id),
        revision,
        error,
    ))
}

fn conditional_write<F>(
    path: &PinnedPath,
    expected: &str,
    consistency: FileConsistency,
    budget: &Budget,
    transform: F,
) -> anyhow::Result<String>
where
    F: FnOnce(&[u8]) -> anyhow::Result<Vec<u8>>,
{
    ensure!(
        matches!(
            consistency,
            FileConsistency::ConditionalInPlace | FileConsistency::Transactional
        ),
        "exact revision preconditions cannot be combined with unconditional atomic replacement"
    );
    let mut transaction = if consistency == FileConsistency::Transactional {
        Some(Transaction::new(budget)?)
    } else {
        None
    };
    let mut file = path.open(GENERIC_READ.0 | GENERIC_WRITE.0, transaction.as_ref().map(|tx| tx.handle))
        .context("conditional open failed; transactional mode additionally requires a TxF-supported volume and file")?;
    let original = snapshot(&mut file, MAX_FILE_BYTES, budget)?;
    check_revision(&original.revision, expected)?;
    let links: FILE_STANDARD_INFO = file_info(&file, FileStandardInfo)?;
    ensure!(links.NumberOfLinks <= 1, "conditional content writes to multiply-linked files are unsupported; replace the explicitly named link instead");
    let data = transform(&original.data)?;
    ensure!(
        data.len() <= MAX_FILE_BYTES,
        "result exceeds the file size limit"
    );
    let mut written = WriteProgress::default();
    let mutation = write_contents(&mut file, &data, budget, &mut written)
        .and_then(|()| preserve_write_metadata(&file, original.basic));
    drop(file);
    if let Err(error) = mutation {
        let transactional = transaction.is_some();
        drop(transaction);
        return Ok(mutation_result(
            path_string(&path.path)?,
            consistency,
            !transactional && written.accepted,
            if transactional { 0 } else { written.bytes },
            Some(original.identity),
            None,
            Some(format!(
                "{error:#}; {}",
                if transactional {
                    "transaction was not committed"
                } else {
                    "in-place contents may be partially changed"
                }
            )),
        ));
    }
    if let Some(tx) = transaction.as_mut() {
        budget.check()?;
        tx.commit()
            .context("transaction commit failed; do not assume the contents changed")?;
    }
    drop(transaction);
    let observed = observe_written(path, &original.identity, &data, budget);
    let (revision, error) = match observed {
        Ok(revision) => (Some(revision), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    Ok(mutation_result(
        path_string(&path.path)?,
        consistency,
        true,
        written.bytes,
        Some(original.identity),
        revision,
        error,
    ))
}

pub fn write(input: FsWriteInput) -> anyhow::Result<String> {
    let conditional = matches!(
        input.consistency,
        FileConsistency::ConditionalInPlace | FileConsistency::Transactional
    );
    ensure!(
        conditional == input.expected_revision.is_some(),
        "conditional modes require expected_revision; create_new and atomic_replace forbid it"
    );
    if input.consistency == FileConsistency::AtomicReplace {
        ensure!(input.metadata == Some(WriteMetadata::DestinationDefaults), "atomic_replace requires explicit metadata=destination_defaults; preserving the existing object requires conditional_in_place");
    } else {
        ensure!(
            input.metadata.unwrap_or(WriteMetadata::Preserve) == WriteMetadata::Preserve
                || input.consistency == FileConsistency::CreateNew,
            "conditional writes preserve metadata and security"
        );
    }
    let budget = Budget::new(input.timeout_ms)?;
    let path = PinnedPath::new(&input.path, &budget)?;
    if let Some(expected) = &input.expected_revision {
        conditional_write(&path, expected, input.consistency, &budget, |original| {
            let old_bom = if matches!(input.bom, WriteBom::Preserve)
                && input.encoding != FileEncoding::Base64
            {
                decode(original, input.encoding)?.1
            } else {
                false
            };
            encode(&input.data, input.encoding, input.bom, old_bom)
        })
    } else {
        let data = encode(&input.data, input.encoding, input.bom, false)?;
        publish_data(&path, &data, input.consistency, &budget)
    }
}

fn patch_data(data: &[u8], input: &FsPatchInput) -> anyhow::Result<Vec<u8>> {
    ensure!(
        input.encoding != FileEncoding::Base64,
        "patch operates on text; use fs_write for binary bytes"
    );
    ensure!(!input.find.is_empty(), "find must not be empty");
    ensure!(
        input.find.len() <= MAX_FILE_BYTES && input.replacement.len() <= MAX_FILE_BYTES,
        "patch input exceeds the size limit"
    );
    ensure!(
        (1..=10_000).contains(&input.expected_matches),
        "expected_matches must be 1..10000"
    );
    let (text, bom) = decode(data, input.encoding)?;
    let matches = text.match_indices(&input.find).count();
    ensure!(
        matches == input.expected_matches as usize,
        "match count conflict: expected {}, observed {matches}",
        input.expected_matches
    );
    let added = input
        .replacement
        .len()
        .checked_mul(matches)
        .context("patch length overflow")?;
    let removed = input
        .find
        .len()
        .checked_mul(matches)
        .context("patch length overflow")?;
    let output_len = text
        .len()
        .checked_sub(removed)
        .and_then(|n| n.checked_add(added))
        .context("patch length overflow")?;
    ensure!(
        output_len <= MAX_FILE_BYTES * 2,
        "patched text exceeds the size limit"
    );
    let text = text.replace(&input.find, &input.replacement);
    encode(&text, input.encoding, WriteBom::Preserve, bom)
}

pub fn patch(input: FsPatchInput) -> anyhow::Result<String> {
    let budget = Budget::new(input.timeout_ms)?;
    let path = PinnedPath::new(&input.path, &budget)?;
    conditional_write(
        &path,
        &input.expected_revision,
        input.consistency,
        &budget,
        |data| patch_data(data, &input),
    )
}

struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                if !LocalFree(Some(HLOCAL(self.0))).is_invalid() {
                    tracing::error!("LocalFree failed for security allocation");
                }
            }
        }
    }
}

struct OwnedSid(LocalAllocation);

impl OwnedSid {
    fn parse(value: &str) -> anyhow::Result<Self> {
        ensure!(value.len() <= 256, "SID exceeds the length limit");
        check_string(value, "SID")?;
        let wide = to_wide(value);
        let mut sid = PSID::default();
        unsafe {
            ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut sid)?;
        }
        Ok(Self(LocalAllocation(sid.0)))
    }

    fn get(&self) -> PSID {
        PSID(self.0 .0)
    }
}

struct SecuritySnapshot {
    descriptor: LocalAllocation,
    owner: PSID,
    group: PSID,
    dacl: *mut ACL,
    control: u16,
}

fn security_snapshot(file: &File) -> anyhow::Result<SecuritySnapshot> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut owner = PSID::default();
    let mut group = PSID::default();
    let mut dacl = std::ptr::null_mut();
    unsafe {
        win32_result(GetSecurityInfo(
            handle(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            Some(&mut group),
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        ))?;
        let allocation = LocalAllocation(descriptor.0);
        let mut control = 0;
        let mut revision = 0;
        GetSecurityDescriptorControl(descriptor, &mut control, &mut revision)?;
        Ok(SecuritySnapshot {
            descriptor: allocation,
            owner,
            group,
            dacl,
            control,
        })
    }
}

fn sid_string(sid: PSID) -> anyhow::Result<String> {
    ensure!(
        !sid.0.is_null(),
        "security descriptor does not contain a SID"
    );
    let mut text = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut text)?;
        let _allocation = LocalAllocation(text.0.cast());
        Ok(super::from_wide(text.0))
    }
}

fn sid_account(sid: PSID) -> anyhow::Result<String> {
    let mut name_len = 0;
    let mut domain_len = 0;
    let mut kind = SID_NAME_USE::default();
    unsafe {
        let result = LookupAccountSidW(
            None,
            sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut kind,
        );
        if let Err(error) = result {
            ensure!(
                error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult(),
                "{error}"
            );
        }
        ensure!(
            name_len <= 32_768 && domain_len <= 32_768,
            "account name exceeds the size limit"
        );
        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len.max(1) as usize];
        LookupAccountSidW(
            None,
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )?;
        let name = String::from_utf16(&name[..name_len as usize])?;
        let domain = String::from_utf16(&domain[..domain_len as usize])?;
        Ok(if domain.is_empty() {
            name
        } else {
            format!("{domain}\\{name}")
        })
    }
}

fn sid_identity(sid: PSID) -> anyhow::Result<SidIdentity> {
    let (account, account_lookup_error) = match sid_account(sid) {
        Ok(account) => (Some(account), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    Ok(SidIdentity {
        sid: sid_string(sid)?,
        account,
        account_lookup_error,
    })
}

fn security_sddl(snapshot: &SecuritySnapshot) -> anyhow::Result<String> {
    let mut text = PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(snapshot.descriptor.0),
            1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )?;
        let _allocation = LocalAllocation(text.0.cast());
        Ok(super::from_wide(text.0))
    }
}

fn acl_aces(dacl: *const ACL) -> anyhow::Result<Vec<AclAce>> {
    if dacl.is_null() {
        return Ok(Vec::new());
    }
    let count = unsafe { (*dacl).AceCount as u32 };
    ensure!(count <= 512, "ACL exceeds the 512 ACE output limit");
    let mut entries = Vec::new();
    for index in 0..count {
        crate::runtime::checkpoint()?;
        unsafe {
            let mut ace = std::ptr::null_mut();
            GetAce(dacl, index, &mut ace)?;
            let header = &*ace.cast::<ACE_HEADER>();
            ensure!(
                header.AceSize as usize >= std::mem::size_of::<ACE_HEADER>(),
                "invalid ACE length"
            );
            let bytes = std::slice::from_raw_parts(ace.cast::<u8>(), header.AceSize as usize);
            let (rights, trustee) = if header.AceType <= 1 {
                ensure!(
                    bytes.len() >= std::mem::size_of::<ACCESS_ALLOWED_ACE>(),
                    "truncated access ACE"
                );
                let access = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                let sid = PSID((&access.SidStart as *const u32).cast_mut().cast());
                ensure!(
                    IsValidSid(sid).as_bool() && GetLengthSid(sid) as usize <= bytes.len() - 8,
                    "invalid ACE SID"
                );
                (Some(access.Mask), Some(sid_identity(sid)?))
            } else {
                (None, None)
            };
            entries.push(AclAce {
                ace_type: header.AceType,
                flags: header.AceFlags,
                rights,
                trustee,
                raw_base64: STANDARD.encode(bytes),
            });
        }
    }
    Ok(entries)
}

fn security_value(file: &File, path: &str) -> anyhow::Result<serde_json::Value> {
    let snapshot = security_snapshot(file)?;
    let id = identity(file)?;
    let sddl = security_sddl(&snapshot)?;
    let revision = format!(
        "sd1:{}:{}:{}",
        id.volume_serial,
        id.file_id,
        digest(sddl.as_bytes())?
    );
    Ok(json!({
        "path": path, "identity": id, "security_revision": revision,
        "owner": sid_identity(snapshot.owner)?, "group": sid_identity(snapshot.group)?,
        "dacl_null": snapshot.dacl.is_null(),
        "inheritance_protected": snapshot.control & SE_DACL_PROTECTED.0 != 0,
        "sddl": sddl, "aces": acl_aces(snapshot.dacl)?,
        "sacl": "not_requested",
    }))
}

pub fn security(path: &str) -> anyhow::Result<String> {
    let budget = Budget::new(None)?;
    let pinned = PinnedPath::new(path, &budget)?;
    let file = pinned.open(READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0, None)?;
    reject_reparse(&file)?;
    Ok(pretty(&security_value(&file, path)?))
}

pub fn permissions(path: &str) -> anyhow::Result<String> {
    let budget = Budget::new(None)?;
    let absolute = std::path::absolute(path)?;
    let pinned = PinnedPath::new(path_string(&absolute)?, &budget)?;
    let file = pinned.open(READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0, None)?;
    reject_reparse(&file)?;
    let snapshot = security_snapshot(&file)?;
    ensure!(!snapshot.dacl.is_null(), "file has a null DACL granting unrestricted access; fs_security reports the descriptor explicitly");
    let entries: Vec<_> = acl_aces(snapshot.dacl)?
        .into_iter()
        .map(|ace| {
            let reference = ace
                .trustee
                .as_ref()
                .map(|s| s.account.as_ref().unwrap_or(&s.sid).clone());
            json!({
                "FileSystemRights": ace.rights,
                "AccessControlType": if ace.ace_type <= 1 { Some(ace.ace_type) } else { None },
                "IdentityReference": reference,
                "IsInherited": u32::from(ace.flags) & INHERITED_ACE.0 != 0,
                "InheritanceFlags": ((ace.flags & 1) << 1) | ((ace.flags & 2) >> 1),
                "PropagationFlags": (ace.flags & 12) >> 2,
                "AceType": ace.ace_type, "NativeFlags": ace.flags, "RawAceBase64": ace.raw_base64,
            })
        })
        .collect();
    Ok(pretty(&json!(entries)))
}

struct SecurityTarget {
    path: String,
    identity: FileIdentity,
}

struct SecurityPlan {
    root: String,
    root_identity: FileIdentity,
    targets: Vec<SecurityTarget>,
    errors: Vec<serde_json::Value>,
    limited: bool,
}

fn security_plan(
    path: &str,
    scope: TargetScope,
    max_depth: Option<u32>,
    max_targets: Option<u32>,
    budget: &Budget,
) -> anyhow::Result<SecurityPlan> {
    let depth_limit = max_depth.unwrap_or(16);
    let target_limit = max_targets.unwrap_or(128) as usize;
    ensure!((1..=32).contains(&depth_limit), "max_depth must be 1..32");
    ensure!(
        (1..=512).contains(&target_limit),
        "max_targets must be 1..512"
    );
    let pinned = PinnedPath::new(path, budget)?;
    let root_file = pinned.open(FILE_READ_ATTRIBUTES.0, None)?;
    reject_reparse(&root_file)?;
    ensure!(
        scope == TargetScope::SelfOnly
            || basic_info(&root_file)?.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
        "children/recursive scope requires a directory"
    );
    let mut plan = SecurityPlan {
        root: path.to_owned(),
        root_identity: identity(&root_file)?,
        targets: Vec::new(),
        errors: Vec::new(),
        limited: false,
    };
    drop(root_file);
    drop(pinned);
    let mut queue = VecDeque::from([(path.to_owned(), 0)]);
    let mut visited = 0;
    while let Some((current, depth)) = queue.pop_front() {
        if let Err(error) = budget.check() {
            plan.errors
                .push(json!({"path": current, "error": format!("{error:#}")}));
            plan.limited = true;
            break;
        }
        visited += 1;
        if visited > target_limit + usize::from(scope == TargetScope::Children) {
            plan.limited = true;
            break;
        }
        let result = (|| -> anyhow::Result<()> {
            let pinned = PinnedPath::new(&current, budget)?;
            let file = pinned.open(FILE_READ_ATTRIBUTES.0, None)?;
            reject_reparse(&file)?;
            if depth != 0 || scope != TargetScope::Children {
                plan.targets.push(SecurityTarget {
                    path: current.clone(),
                    identity: identity(&file)?,
                });
            }
            let directory = basic_info(&file)?.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
            let recurse =
                scope == TargetScope::Recursive || scope == TargetScope::Children && depth == 0;
            if directory && recurse {
                for entry in std::fs::read_dir(&pinned.path)? {
                    budget.check()?;
                    let entry = entry?;
                    if depth >= depth_limit
                        || queue.len() + visited
                            >= target_limit + usize::from(scope == TargetScope::Children)
                    {
                        plan.limited = true;
                        break;
                    }
                    queue.push_back((path_string(&entry.path())?.to_owned(), depth + 1));
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            plan.errors
                .push(json!({"path": current, "error": format!("{error:#}")}));
        }
    }
    Ok(plan)
}

fn apply_security<F>(
    plan: SecurityPlan,
    scope: TargetScope,
    budget: &Budget,
    mut change: F,
) -> anyhow::Result<String>
where
    F: FnMut(&File) -> anyhow::Result<()>,
{
    let mut results = plan.errors;
    let mut changed = 0;
    for target in plan.targets {
        let mut accepted = false;
        let result = (|| -> anyhow::Result<serde_json::Value> {
            budget.check()?;
            let root = PinnedPath::new(&plan.root, budget)?;
            let root_file = root.open(FILE_READ_ATTRIBUTES.0, None)?;
            ensure!(
                identity(&root_file)? == plan.root_identity,
                "scope root identity changed"
            );
            let _scope_root = (target.path != plan.root).then_some((root, root_file));
            let pinned = PinnedPath::new(&target.path, budget)?;
            // MAXIMUM_ALLOWED suppresses SetSecurityInfo's implicit child propagation.
            // Apply only the bounded, identity-checked targets collected above.
            let file = pinned.open(MAXIMUM_ALLOWED, None)?;
            reject_reparse(&file)?;
            ensure!(
                identity(&file)? == target.identity,
                "target identity changed since traversal"
            );
            change(&file)?;
            accepted = true;
            let observed = security_value(&file, &target.path)?;
            Ok(json!({
                "path": target.path, "identity": target.identity, "accepted": true,
                "security_revision": observed["security_revision"], "owner": observed["owner"],
                "inheritance_protected": observed["inheritance_protected"],
            }))
        })();
        match result {
            Ok(result) => {
                changed += 1;
                results.push(result);
            }
            Err(error) => results.push(
                json!({"path": target.path, "accepted": accepted, "error": format!("{error:#}")}),
            ),
        }
    }
    let failed = results.iter().filter(|r| r.get("error").is_some()).count();
    Ok(pretty(&json!({
        "scope": scope, "outcome": if failed == 0 && !plan.limited { "completed" } else { "partial" },
        "changed": changed, "failed": failed, "traversal_limited": plan.limited,
        "atomicity": "per_target", "reparse_points_followed": false, "results": results,
    })))
}

fn validate_ace(entry: &AclEntry) -> anyhow::Result<()> {
    let flags = entry.inheritance_flags.unwrap_or(0);
    ensure!(
        flags & !0x0f == 0,
        "only OI=1, CI=2, NP=4 and IO=8 ACE flags are supported"
    );
    ensure!(
        flags & 12 == 0 || flags & 3 != 0,
        "inherit-only/no-propagate requires object or container inheritance"
    );
    ensure!(
        entry.rights & !0xf11f01ff == 0,
        "unsupported file access mask bits"
    );
    if entry.mode == AceMode::Revoke {
        ensure!(
            entry.rights == 0 && flags == 0,
            "revoke requires zero rights and inheritance flags"
        );
    } else {
        ensure!(entry.rights != 0, "access ACE rights must be nonzero");
    }
    Ok(())
}

fn acl_template(
    snapshot: &SecuritySnapshot,
    edit: AclEdit,
    inheritance: DaclInheritance,
) -> anyhow::Result<Vec<usize>> {
    ensure!(
        edit == AclEdit::Replace || !snapshot.dacl.is_null(),
        "merge cannot safely modify a null DACL; explicitly use replace"
    );
    let size = if edit == AclEdit::Merge {
        unsafe { (*snapshot.dacl).AclSize as usize }
    } else {
        std::mem::size_of::<ACL>()
    };
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let new_acl = storage.as_mut_ptr().cast::<ACL>();
    unsafe {
        InitializeAcl(new_acl, size as u32, ACL_REVISION_DS)?;
        if edit == AclEdit::Merge {
            for index in 0..(*snapshot.dacl).AceCount as u32 {
                let mut ace = std::ptr::null_mut();
                GetAce(snapshot.dacl, index, &mut ace)?;
                let header = &*ace.cast::<ACE_HEADER>();
                let inherited = u32::from(header.AceFlags) & INHERITED_ACE.0 != 0;
                if inherited
                    && matches!(
                        inheritance,
                        DaclInheritance::ProtectRemove | DaclInheritance::Enable
                    )
                {
                    continue;
                }
                let mut bytes =
                    std::slice::from_raw_parts(ace.cast::<u8>(), header.AceSize as usize).to_vec();
                if inherited && inheritance == DaclInheritance::ProtectCopy {
                    bytes[1] &= !(INHERITED_ACE.0 as u8);
                }
                AddAce(
                    new_acl,
                    ACL_REVISION_DS,
                    u32::MAX,
                    bytes.as_ptr().cast(),
                    bytes.len() as u32,
                )?;
            }
        }
    }
    Ok(storage)
}

pub fn acl_modify(input: FsAclInput) -> anyhow::Result<String> {
    ensure!(
        input.entries.len() <= 256,
        "at most 256 explicit ACE changes per request"
    );
    ensure!(
        !(input.mode == AclEdit::Merge
            && input.entries.is_empty()
            && input.inheritance == DaclInheritance::Preserve),
        "no ACL change was requested"
    );
    for entry in &input.entries {
        validate_ace(entry)?;
    }
    let sids: Vec<_> = input
        .entries
        .iter()
        .map(|entry| OwnedSid::parse(&entry.sid))
        .collect::<anyhow::Result<_>>()?;
    let explicit: Vec<_> = input
        .entries
        .iter()
        .zip(&sids)
        .map(|(entry, sid)| EXPLICIT_ACCESS_W {
            grfAccessPermissions: entry.rights,
            grfAccessMode: match entry.mode {
                AceMode::Grant => GRANT_ACCESS,
                AceMode::Set => SET_ACCESS,
                AceMode::Deny => DENY_ACCESS,
                AceMode::Revoke => REVOKE_ACCESS,
            },
            grfInheritance: ACE_FLAGS(u32::from(entry.inheritance_flags.unwrap_or(0))),
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: PWSTR(sid.get().0.cast()),
                ..Default::default()
            },
        })
        .collect();
    let budget = Budget::new(input.timeout_ms)?;
    let plan = security_plan(
        &input.path,
        input.scope,
        input.max_depth,
        input.max_targets,
        &budget,
    )?;
    apply_security(plan, input.scope, &budget, |file| {
        let directory = basic_info(file)?.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        ensure!(
            directory
                || input
                    .entries
                    .iter()
                    .all(|e| e.inheritance_flags.unwrap_or(0) == 0),
            "inheritance flags on a file are unsupported"
        );
        let original = security_snapshot(file)?;
        let mut template = acl_template(&original, input.mode, input.inheritance)?;
        let mut dacl = template.as_mut_ptr().cast::<ACL>();
        let mut allocation = None;
        if !explicit.is_empty() {
            unsafe {
                win32_result(SetEntriesInAclW(Some(&explicit), Some(dacl), &mut dacl))?;
            }
            allocation = Some(LocalAllocation(dacl.cast()));
        }
        ensure!(
            !dacl.is_null(),
            "refusing to install an unintended null DACL"
        );
        let protection = match input.inheritance {
            DaclInheritance::ProtectCopy | DaclInheritance::ProtectRemove => {
                PROTECTED_DACL_SECURITY_INFORMATION
            }
            DaclInheritance::Enable => UNPROTECTED_DACL_SECURITY_INFORMATION,
            DaclInheritance::Preserve => {
                if original.control & SE_DACL_PROTECTED.0 != 0 {
                    PROTECTED_DACL_SECURITY_INFORMATION
                } else {
                    UNPROTECTED_DACL_SECURITY_INFORMATION
                }
            }
        };
        budget.check()?;
        unsafe {
            win32_result(SetSecurityInfo(
                handle(file),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | protection,
                None,
                None,
                Some(dacl),
                None,
            ))?;
        }
        drop(allocation);
        Ok(())
    })
}

pub fn owner_modify(input: FsOwnerInput) -> anyhow::Result<String> {
    let owner = OwnedSid::parse(&input.owner_sid)?;
    let budget = Budget::new(input.timeout_ms)?;
    let plan = security_plan(
        &input.path,
        input.scope,
        input.max_depth,
        input.max_targets,
        &budget,
    )?;
    apply_security(plan, input.scope, &budget, |file| {
        budget.check()?;
        unsafe {
            win32_result(SetSecurityInfo(
                handle(file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(owner.get()),
                None,
                None,
                None,
            ))
        }
    })
}

struct FindHandle(HANDLE);

impl Drop for FindHandle {
    fn drop(&mut self) {
        if let Err(error) = unsafe { FindClose(self.0) } {
            tracing::error!(%error, "filesystem enumeration close failed");
        }
    }
}

fn ensure_no_streams(path: &Path) -> anyhow::Result<()> {
    let wide = to_wide(path_string(path)?);
    let mut stream = WIN32_FIND_STREAM_DATA::default();
    let first = unsafe {
        FindFirstStreamW(
            PCWSTR(wide.as_ptr()),
            FindStreamInfoStandard,
            &mut stream as *mut _ as *mut _,
            None,
        )
    };
    let search = match first {
        Ok(search) => FindHandle(search),
        Err(error) if error.code() == ERROR_HANDLE_EOF.to_hresult() => return Ok(()),
        Err(error) => {
            return Err(error).context("could not verify alternate stream metadata before copy")
        }
    };
    loop {
        ensure!(
            wchar_to_string(&stream.cStreamName) == "::$DATA",
            "copying files with alternate data streams is unsupported; no streams were discarded"
        );
        match unsafe { FindNextStreamW(search.0, &mut stream as *mut _ as *mut _) } {
            Ok(()) => {}
            Err(error) if error.code() == ERROR_HANDLE_EOF.to_hresult() => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn copy_security(
    source_file: &File,
    destination: &File,
    security: CopySecurity,
) -> anyhow::Result<()> {
    if security == CopySecurity::Source {
        let original = security_snapshot(source_file)?;
        ensure!(
            !original.dacl.is_null(),
            "copying a null source DACL is unsupported"
        );
        unsafe {
            win32_result(SetSecurityInfo(
                handle(destination),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                Some(original.owner),
                Some(original.group),
                Some(original.dacl),
                None,
            ))?;
        }
    }
    Ok(())
}

fn copy_basic(source: &Snapshot, destination: &File) -> anyhow::Result<()> {
    const SUPPORTED: u32 = FILE_ATTRIBUTE_READONLY.0
        | FILE_ATTRIBUTE_HIDDEN.0
        | FILE_ATTRIBUTE_SYSTEM.0
        | FILE_ATTRIBUTE_ARCHIVE.0
        | FILE_ATTRIBUTE_NORMAL.0
        | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.0
        | FILE_ATTRIBUTE_TEMPORARY.0;
    ensure!(
        source.basic.FileAttributes & !SUPPORTED == 0,
        "copying compressed, encrypted, sparse, offline or other special attributes are unsupported"
    );
    let basic = FILE_BASIC_INFO {
        ChangeTime: 0,
        ..source.basic
    };
    unsafe {
        SetFileInformationByHandle(
            handle(destination),
            FileBasicInfo,
            &basic as *const _ as *const _,
            std::mem::size_of_val(&basic) as u32,
        )?;
    }
    Ok(())
}

fn transfer_batch<F>(
    files: Vec<FileTransfer>,
    continue_on_error: bool,
    budget: &Budget,
    mut operation: F,
) -> anyhow::Result<String>
where
    F: FnMut(&FileTransfer, &Budget, &mut usize) -> anyhow::Result<serde_json::Value>,
{
    ensure!(
        !files.is_empty() && files.len() <= MAX_BATCH,
        "files must contain 1..{MAX_BATCH} entries"
    );
    let requested = files.len();
    let mut results = Vec::new();
    let mut total_bytes = 0;
    for file in files {
        let result = budget
            .check()
            .and_then(|()| operation(&file, budget, &mut total_bytes));
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                json!({"source": file.source, "destination": file.destination, "outcome": "failed", "accepted": false, "error": format!("{error:#}")})
            }
        };
        let failed = result["outcome"] != "completed";
        results.push(result);
        if failed && !continue_on_error {
            break;
        }
    }
    let completed = results
        .iter()
        .filter(|r| r["outcome"] == "completed")
        .count();
    Ok(pretty(&json!({
        "outcome": if completed == requested { "completed" } else { "partial" },
        "atomicity": "per_file", "requested": requested, "completed": completed,
        "not_attempted": requested - results.len(), "results": results,
    })))
}

fn count_transfer(bytes: usize, total: &mut usize) -> anyhow::Result<()> {
    *total = total
        .checked_add(bytes)
        .context("transfer length overflow")?;
    ensure!(
        *total <= MAX_BATCH_BYTES,
        "batch exceeds the {MAX_BATCH_BYTES} byte limit"
    );
    Ok(())
}

pub fn copy(input: FsCopyInput) -> anyhow::Result<String> {
    let budget = Budget::new(input.timeout_ms)?;
    transfer_batch(
        input.files,
        input.continue_on_error,
        &budget,
        |item, budget, total| {
            let source = PinnedPath::new(&item.source, budget)?;
            let destination = PinnedPath::new(&item.destination, budget)?;
            let mut source_file = source.open(
                GENERIC_READ.0
                    | if input.security == CopySecurity::Source {
                        READ_CONTROL.0
                    } else {
                        0
                    },
                None,
            )?;
            let original = snapshot(&mut source_file, MAX_FILE_BYTES, budget)?;
            check_revision(&original.revision, &item.expected_revision)?;
            count_transfer(original.data.len(), total)?;
            ensure_no_streams(&source.path)?;
            let mut temporary = TemporaryFile::new(&destination)?;
            let id = identity(&temporary.file)?;
            let mut written = WriteProgress::default();
            let preparation = copy_security(&source_file, &temporary.file, input.security)
                .and_then(|()| {
                    write_contents(&mut temporary.file, &original.data, budget, &mut written)
                })
                .and_then(|()| copy_basic(&original, &temporary.file))
                .and_then(|()| Ok(temporary.file.sync_all()?))
                .and_then(|()| budget.check())
                .and_then(|()| temporary.publish(&destination, false));
            if let Err(error) = preparation {
                return Err(match temporary.cleanup() {
                    Ok(()) => error,
                    Err(cleanup) => error.context(format!(
                        "temporary cleanup failed for {}: {cleanup:#}",
                        temporary.path.display()
                    )),
                });
            }
            drop(temporary);
            let observed = observe_written(&destination, &id, &original.data, budget);
            let (revision, error) = match observed {
                Ok(revision) => (Some(revision), None),
                Err(error) => (None, Some(format!("{error:#}"))),
            };
            Ok(json!({
                "source": item.source, "destination": item.destination, "accepted": true,
                "outcome": if error.is_none() { "completed" } else { "partial_or_unobserved" },
                "identity": id, "revision": revision, "bytes_written": written.bytes,
                "atomicity": "atomic_namespace_publication", "metadata": "source_basic_attributes_and_timestamps",
                "security": if input.security == CopySecurity::Source { "source_owner_group_dacl_protected" } else { "destination_defaults" },
                "sacl": "destination_defaults", "error": error,
            }))
        },
    )
}

pub fn move_files(input: FsMoveInput) -> anyhow::Result<String> {
    let budget = Budget::new(input.timeout_ms)?;
    transfer_batch(
        input.files,
        input.continue_on_error,
        &budget,
        |item, budget, total| {
            let source = PinnedPath::new(&item.source, budget)?;
            let destination = PinnedPath::new(&item.destination, budget)?;
            let mut file = source.open(GENERIC_READ.0 | DELETE.0, None)?;
            let original = snapshot(&mut file, MAX_FILE_BYTES, budget)?;
            check_revision(&original.revision, &item.expected_revision)?;
            count_transfer(original.data.len(), total)?;
            budget.check()?;
            rename_handle(&file, &destination.path, false)
                .context("same-volume, absent-destination rename failed")?;
            drop(file);
            let observed =
                observe_written(&destination, &original.identity, &original.data, budget);
            let (revision, error) = match observed {
                Ok(revision) => (Some(revision), None),
                Err(error) => (None, Some(format!("{error:#}"))),
            };
            Ok(json!({
                "source": item.source, "destination": item.destination, "accepted": true,
                "outcome": if error.is_none() { "completed" } else { "partial_or_unobserved" },
                "identity": original.identity, "revision": revision, "metadata": "preserved",
                "atomicity": "single_file_same_volume_rename", "error": error,
            }))
        },
    )
}

fn reparse_data(file: &File) -> anyhow::Result<Vec<u8>> {
    let attrs: FILE_ATTRIBUTE_TAG_INFO = file_info(file, FileAttributeTagInfo)?;
    if attrs.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0 {
        return Ok(Vec::new());
    }
    let mut data = vec![0u8; 16 * 1024];
    let mut returned = 0;
    unsafe {
        windows::Win32::System::IO::DeviceIoControl(
            handle(file),
            windows::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT,
            None,
            0,
            Some(data.as_mut_ptr().cast()),
            data.len() as u32,
            Some(&mut returned),
            None,
        )?;
    }
    ensure!(
        returned as usize <= data.len() && returned >= 8,
        "invalid reparse data length"
    );
    data.truncate(returned as usize);
    let length = u16::from_le_bytes([data[4], data[5]]) as usize;
    ensure!(length + 8 <= data.len(), "truncated reparse data");
    data.truncate(length + 8);
    Ok(data)
}

fn reparse_name(data: &[u8], header: usize, offset_at: usize) -> anyhow::Result<String> {
    ensure!(data.len() >= offset_at + 4, "truncated reparse path header");
    let offset = u16::from_le_bytes([data[offset_at], data[offset_at + 1]]) as usize;
    let length = u16::from_le_bytes([data[offset_at + 2], data[offset_at + 3]]) as usize;
    ensure!(
        offset.is_multiple_of(2)
            && length.is_multiple_of(2)
            && header + offset + length <= data.len(),
        "invalid reparse path bounds"
    );
    let units: Vec<_> = data[header + offset..header + offset + length]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    Ok(String::from_utf16(&units)?)
}

fn link_value(file: &File, path: &str) -> anyhow::Result<serde_json::Value> {
    let id = identity(file)?;
    let basic = basic_info(file)?;
    let standard: FILE_STANDARD_INFO = file_info(file, FileStandardInfo)?;
    let attrs: FILE_ATTRIBUTE_TAG_INFO = file_info(file, FileAttributeTagInfo)?;
    let data = reparse_data(file)?;
    let revision = format!(
        "link1:{}:{}:{:x}:{:x}:{:x}:{}",
        id.volume_serial,
        id.file_id,
        basic.CreationTime,
        basic.ChangeTime,
        basic.FileAttributes,
        digest(&data)?
    );
    let (kind, target, print_name, relative) = match attrs.ReparseTag {
        IO_REPARSE_TAG_SYMLINK => {
            ensure!(data.len() >= 20, "truncated symbolic link data");
            let flags = u32::from_le_bytes(data[16..20].try_into()?);
            (
                "symbolic_link",
                Some(reparse_name(&data, 20, 8)?),
                Some(reparse_name(&data, 20, 12)?),
                flags & 1 != 0,
            )
        }
        IO_REPARSE_TAG_MOUNT_POINT => (
            "junction_or_mount_point",
            Some(reparse_name(&data, 16, 8)?),
            Some(reparse_name(&data, 16, 12)?),
            false,
        ),
        0 if standard.NumberOfLinks > 1 => ("hard_link", None, None, false),
        0 => ("regular_file", None, None, false),
        _ => ("unsupported_reparse_point", None, None, false),
    };
    Ok(json!({
        "path": path, "identity": id, "revision": revision, "kind": kind,
        "target": target, "print_name": print_name, "relative": relative,
        "link_count": standard.NumberOfLinks, "reparse_tag": attrs.ReparseTag,
        "is_directory": basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
        "raw_reparse_base64": STANDARD.encode(data),
    }))
}

pub fn link_inspect(path: &str) -> anyhow::Result<String> {
    let budget = Budget::new(None)?;
    let pinned = PinnedPath::new(path, &budget)?;
    let file = pinned.open(FILE_READ_ATTRIBUTES.0, None)?;
    Ok(pretty(&link_value(&file, path)?))
}

pub fn link_create(input: FsLinkCreateInput) -> anyhow::Result<String> {
    let budget = Budget::new(None)?;
    let destination = PinnedPath::new(&input.path, &budget)?;
    check_string(&input.target, "target")?;
    let dest_wide = to_wide(path_string(&destination.path)?);
    let mut expected_identity = None;
    if input.kind == LinkKind::Hard {
        let expected = input
            .expected_target_revision
            .as_deref()
            .context("hard links require expected_target_revision")?;
        let source = PinnedPath::new(&input.target, &budget)?;
        let mut file = source.open(GENERIC_READ.0, None)?;
        let original = snapshot(&mut file, MAX_FILE_BYTES, &budget)?;
        check_revision(&original.revision, expected)?;
        expected_identity = Some(original.identity);
        let source_wide = to_wide(path_string(&source.path)?);
        budget.check()?;
        unsafe {
            CreateHardLinkW(
                PCWSTR(dest_wide.as_ptr()),
                PCWSTR(source_wide.as_ptr()),
                None,
            )?;
        }
    } else {
        ensure!(input.expected_target_revision.is_none(), "symbolic links store a target string without following it; expected_target_revision applies only to hard links");
        let target_wide = to_wide(&input.target);
        let flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
            | if input.kind == LinkKind::SymbolicDirectory {
                SYMBOLIC_LINK_FLAG_DIRECTORY
            } else {
                SYMBOLIC_LINK_FLAGS(0)
            };
        budget.check()?;
        if !unsafe {
            CreateSymbolicLinkW(
                PCWSTR(dest_wide.as_ptr()),
                PCWSTR(target_wide.as_ptr()),
                flags,
            )
        } {
            return Err(windows::core::Error::from_thread().into());
        }
    }
    let observation = destination.open(FILE_READ_ATTRIBUTES.0, None).and_then(|file| {
        if let Some(expected) = expected_identity {
            ensure!(identity(&file)? == expected, "link creation was accepted, but the destination identity changed before observation");
        }
        let link = link_value(&file, &input.path)?;
        if input.kind != LinkKind::Hard {
            ensure!(
                link["kind"] == "symbolic_link" && link["print_name"] == input.target
                    && link["is_directory"] == (input.kind == LinkKind::SymbolicDirectory),
                "link creation was accepted, but the target changed before observation"
            );
        }
        Ok(link)
    });
    Ok(pretty(&match observation {
        Ok(link) => json!({"outcome": "completed", "accepted": true, "link": link}),
        Err(error) => {
            json!({"outcome": "partial_or_unobserved", "accepted": true, "error": format!("{error:#}")})
        }
    }))
}

pub fn link_remove(input: FsLinkRemoveInput) -> anyhow::Result<String> {
    let budget = Budget::new(None)?;
    let path = PinnedPath::new(&input.path, &budget)?;
    let file = path.open(FILE_READ_ATTRIBUTES.0 | DELETE.0, None)?;
    let link = link_value(&file, &input.path)?;
    check_revision(
        link["revision"].as_str().context("missing link revision")?,
        &input.expected_revision,
    )?;
    ensure!(
        matches!(
            link["kind"].as_str(),
            Some("symbolic_link" | "hard_link" | "junction_or_mount_point")
        ),
        "only symbolic links, junctions or multiply-linked file names can be removed here"
    );
    // Volume mount points require explicit volume management, not junction deletion.
    if link["kind"] == "junction_or_mount_point" {
        let target = link["target"].as_str().context("missing junction target")?;
        ensure!(
            !target.starts_with("\\??\\Volume{"),
            "volume mount points are unsupported by fs_link_remove"
        );
    }
    budget.check()?;
    disposition(&file)?;
    drop(file);
    let observed = path.open(FILE_READ_ATTRIBUTES.0, None);
    let (outcome, error) = match observed {
        Ok(file) => {
            if identity(&file)? != serde_json::from_value::<FileIdentity>(link["identity"].clone())?
            {
                ("removed_path_reused", None)
            } else {
                ("delete_pending", None)
            }
        }
        Err(error)
            if error
                .downcast_ref::<windows::core::Error>()
                .is_some_and(|e| {
                    e.code() == ERROR_FILE_NOT_FOUND.to_hresult()
                        || e.code() == ERROR_PATH_NOT_FOUND.to_hresult()
                }) =>
        {
            ("removed", None)
        }
        Err(error) => ("delete_pending", Some(format!("{error:#}"))),
    };
    Ok(pretty(
        &json!({"path": input.path, "identity": link["identity"], "accepted": true, "outcome": outcome, "error": error}),
    ))
}

struct RestartSession(u32);

impl Drop for RestartSession {
    fn drop(&mut self) {
        let code = unsafe { windows::Win32::System::RestartManager::RmEndSession(self.0) };
        if code != ERROR_SUCCESS {
            tracing::error!(code = code.0, "Restart Manager session cleanup failed");
        }
    }
}

pub fn locks(path: &str) -> anyhow::Result<String> {
    use windows::Win32::System::RestartManager::*;
    let budget = Budget::new(None)?;
    let pinned = PinnedPath::new(path, &budget)?;
    let file = open_path(
        &pinned.path,
        FILE_READ_ATTRIBUTES.0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
    )?;
    reject_reparse(&file)?;
    ensure!(
        basic_info(&file)?.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0,
        "Restart Manager file registration does not support directories"
    );
    let id = identity(&file)?;
    let mut session = 0;
    let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
    unsafe {
        win32_result(RmStartSession(&mut session, None, PWSTR(key.as_mut_ptr())))?;
    }
    let session = RestartSession(session);
    let wide = to_wide(path_string(&pinned.path)?);
    unsafe {
        win32_result(RmRegisterResources(
            session.0,
            Some(&[PCWSTR(wide.as_ptr())]),
            None,
            None,
        ))?;
    }
    let mut processes = Vec::<RM_PROCESS_INFO>::new();
    let mut reboot_reasons = 0;
    for _ in 0..5 {
        budget.check()?;
        let mut needed = 0;
        let mut count = processes.len() as u32;
        let code = unsafe {
            RmGetList(
                session.0,
                &mut needed,
                &mut count,
                if processes.is_empty() {
                    None
                } else {
                    Some(processes.as_mut_ptr())
                },
                &mut reboot_reasons,
            )
        };
        if code == ERROR_MORE_DATA {
            ensure!(
                needed <= 1024,
                "Restart Manager result exceeds the 1024 process limit"
            );
            processes.resize(needed as usize, RM_PROCESS_INFO::default());
            continue;
        }
        win32_result(code)?;
        ensure!(
            count as usize <= processes.len(),
            "invalid Restart Manager result count"
        );
        processes.truncate(count as usize);
        let values: Vec<_> = processes.iter().map(|process| {
            let ticks = (u64::from(process.Process.ProcessStartTime.dwHighDateTime) << 32) | u64::from(process.Process.ProcessStartTime.dwLowDateTime);
            json!({
                "pid": process.Process.dwProcessId, "process_start_filetime": ticks.to_string(),
                "process_identity": if ticks == 0 { None } else { Some(format!("{}:{ticks}", process.Process.dwProcessId)) },
                "identity_complete": ticks != 0,
                "application": wchar_to_string(&process.strAppName), "service": wchar_to_string(&process.strServiceShortName),
                "session_id": process.TSSessionId, "application_type": process.ApplicationType.0,
                "application_status": process.AppStatus, "restartable": process.bRestartable.as_bool(),
            })
        }).collect();
        return Ok(pretty(&json!({
            "path": path, "identity": id, "source": "windows_restart_manager",
            "complete_handle_inventory": false, "shutdown_requested": false,
            "reboot_reasons": reboot_reasons, "processes": values,
        })));
    }
    bail!("Restart Manager resource list kept changing; no complete snapshot was obtained")
}

/// Converts a FILETIME to an ISO 8601 string. FILETIME is 100-nanosecond
/// intervals since January 1, 1601. A date chosen because it's the beginning
/// of a 400-year Gregorian calendar cycle. You know, the thing everyone thinks
/// about when designing a timestamp format. We subtract 116,444,736,000,000,000
/// to get to the Unix epoch because that's how many 100ns intervals there are
/// between 1601 and 1970. I wish I was making this up.
fn filetime_to_iso(ft: &FILETIME) -> String {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    if ticks == 0 {
        return String::new();
    }
    // Convert Windows FILETIME (100ns since 1601) to Unix epoch
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000; // 369 years of bullshit
    if ticks < EPOCH_DIFF {
        return String::new();
    }
    let unix_100ns = ticks - EPOCH_DIFF;
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;

    chrono_format(secs as i64, nanos)
}

/// Formats a Unix timestamp to ISO 8601 WITHOUT the chrono crate because we're
/// not dragging in a dependency just to print a date. Instead we do calendar math
/// by hand like some kind of medieval astronomer. Leap years included. You're welcome.
fn chrono_format(secs: i64, _nanos: u32) -> String {
    // Simple UTC format without chrono dependency
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Days since unix epoch to Y/M/D: implementing the Gregorian calendar
    // from scratch in a filesystem module. This is fine. Everything is fine.
    let mut y = 1970i64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }
    let months_days: [i64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1;
    for &md in &months_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        month += 1;
    }
    let day = remaining_days + 1;
    format!("{y:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Returns whether a year is a leap year. The one function in this entire
/// codebase that actually makes sense.
fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Converts file attribute bitmask to a compact string representation.
/// 'd' for directory, 'r' for read-only, 'h' for hidden, 's' for system,
/// 'a' for archive. It's like Unix file modes except less useful and stored
/// in a DWORD because Windows measures everything in 32-bit chunks of regret.
fn attrs_string(attrs: u32) -> String {
    let mut s = String::new();
    if attrs & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        s.push('d');
    } else {
        s.push('-');
    }
    if attrs & FILE_ATTRIBUTE_READONLY.0 != 0 {
        s.push('r');
    }
    if attrs & FILE_ATTRIBUTE_HIDDEN.0 != 0 {
        s.push('h');
    }
    if attrs & FILE_ATTRIBUTE_SYSTEM.0 != 0 {
        s.push('s');
    }
    if attrs & FILE_ATTRIBUTE_ARCHIVE.0 != 0 {
        s.push('a');
    }
    s
}

/// Lists directory contents using FindFirstFileW/FindNextFileW. This API is
/// literally the same one Windows 95 used. You append "\\*" to the path,
/// call FindFirstFileW, then loop with FindNextFileW until it returns an error.
/// "." and ".." are included in the results because apparently knowing you're
/// in a directory that has a parent is vital information. We filter those out
/// because we're not savages.
pub fn list(path: &str, hidden: bool, recurse: bool) -> anyhow::Result<String> {
    enumerate_files(path, None, hidden, recurse, 500)
}

pub fn search(path: &str, pattern: &str, limit: u32) -> anyhow::Result<String> {
    ensure!((1..=500).contains(&limit), "limit must be 1..500");
    check_string(pattern, "pattern")?;
    ensure!(
        !pattern.contains(['\\', '/', ':']) && pattern.len() <= 255,
        "pattern must be a file-name pattern, not a path"
    );
    enumerate_files(path, Some(pattern), true, true, limit as usize)
}

fn enumerate_directory<F>(
    path: &Path,
    pattern: &str,
    budget: &Budget,
    examined: &mut usize,
    mut entry: F,
) -> anyhow::Result<()>
where
    F: FnMut(&WIN32_FIND_DATAW) -> anyhow::Result<bool>,
{
    let search = path.join(pattern);
    let wide = to_wide(path_string(&search)?);
    let mut data = WIN32_FIND_DATAW::default();
    let search = match unsafe { FindFirstFileW(PCWSTR(wide.as_ptr()), &mut data) } {
        Ok(search) => FindHandle(search),
        Err(error) if error.code() == ERROR_FILE_NOT_FOUND.to_hresult() => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("enumerate {}", path.display())),
    };
    loop {
        budget.check()?;
        *examined += 1;
        ensure!(
            *examined <= 20_000,
            "directory enumeration exceeded 20000 entries"
        );
        let name = wchar_to_string(&data.cFileName);
        if name != "." && name != ".." && !entry(&data)? {
            break;
        }
        match unsafe { FindNextFileW(search.0, &mut data) } {
            Ok(()) => {}
            Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => break,
            Err(error) => {
                return Err(error).with_context(|| format!("enumerate {}", path.display()))
            }
        }
    }
    Ok(())
}

fn enumerate_files(
    path: &str,
    pattern: Option<&str>,
    hidden: bool,
    recurse: bool,
    limit: usize,
) -> anyhow::Result<String> {
    let budget = Budget::new(None)?;
    let absolute = std::path::absolute(path)?;
    let mut queue = VecDeque::from([(absolute, 0)]);
    let mut entries = Vec::new();
    let mut examined = 0;
    while let Some((directory, depth)) = queue.pop_front() {
        budget.check()?;
        let pinned = PinnedPath::new(path_string(&directory)?, &budget)?;
        let file = pinned.open(FILE_READ_ATTRIBUTES.0, None)?;
        reject_reparse(&file)?;
        ensure!(
            basic_info(&file)?.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
            "enumeration target is not a directory"
        );
        enumerate_directory(
            &directory,
            pattern.unwrap_or("*"),
            &budget,
            &mut examined,
            |data| {
                let is_hidden = data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN.0 != 0;
                if hidden || !is_hidden {
                    let name = wchar_to_string(&data.cFileName);
                    let full = directory.join(&name);
                    let is_dir = data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
                    let size = ((data.nFileSizeHigh as u64) << 32) | data.nFileSizeLow as u64;
                    entries.push(json!({
                    "Name": name, "FullName": path_string(&full)?, "Mode": attrs_string(data.dwFileAttributes),
                    "SizeKB": if is_dir && pattern.is_none() { json!(null) } else { json!((size as f64 / 1024.0 * 10.0).round() / 10.0) },
                    "LastWriteTime": filetime_to_iso(&data.ftLastWriteTime),
                    "IsReparsePoint": data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0,
                }));
                }
                Ok(entries.len() < limit)
            },
        )?;
        if entries.len() >= limit {
            break;
        }
        if recurse {
            enumerate_directory(&directory, "*", &budget, &mut examined, |data| {
                if data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
                    && data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0
                    && (hidden || data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN.0 == 0)
                {
                    ensure!(
                        depth < 32 && queue.len() < 4096,
                        "directory traversal depth or queue limit exceeded"
                    );
                    queue.push_back((directory.join(wchar_to_string(&data.cFileName)), depth + 1));
                }
                Ok(true)
            })?;
        }
    }
    Ok(pretty(&json!(entries)))
}

/// Gets detailed info about a single file/directory. Calls FindFirstFileW
/// (yes, FIND, even though we know the exact path; there's no GetFileInfoW
/// that returns a WIN32_FIND_DATAW because that would be convenient). Then
/// calls get_file_owner() which is its own two-API-call adventure to translate
/// a security descriptor into a human-readable "DOMAIN\username" string.
pub fn info(path: &str) -> anyhow::Result<String> {
    check_string(path, "path")?;
    let budget = Budget::new(None)?;
    let absolute = std::path::absolute(path)?;
    let pinned = PinnedPath::new(path_string(&absolute)?, &budget)?;
    let _file = pinned.open(FILE_READ_ATTRIBUTES.0, None)?;
    let wide = to_wide(path);

    unsafe {
        let mut fd = WIN32_FIND_DATAW::default();
        let handle = FindFirstFileW(windows::core::PCWSTR(wide.as_ptr()), &mut fd)?;
        let _ = FindClose(handle);

        let name = wchar_to_string(&fd.cFileName);
        let size = ((fd.nFileSizeHigh as u64) << 32) | fd.nFileSizeLow as u64;
        let is_dir = fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;

        let (owner, owner_error) = match get_file_owner(path) {
            Ok(owner) => (Some(owner), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };

        Ok(pretty(&json!({
            "Name": name,
            "FullName": path,
            "Length": if is_dir { json!(null) } else { json!(size) },
            "Attributes": attrs_string(fd.dwFileAttributes),
            "CreationTime": filetime_to_iso(&fd.ftCreationTime),
            "LastWriteTime": filetime_to_iso(&fd.ftLastWriteTime),
            "LastAccessTime": filetime_to_iso(&fd.ftLastAccessTime),
            "IsDirectory": is_dir,
            "IsReadOnly": fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY.0 != 0,
            "Owner": owner,
            "OwnerError": owner_error,
        })))
    }
}

/// Gets the owner of a file. This is a two-step process because Windows stores
/// ownership as a binary Security Identifier (SID), a variable-length blob of
/// bytes that identifies a user, group, or service. To turn this into something
/// a human can read, you have to:
///   1. Call GetNamedSecurityInfoW to get the SID (also allocates a security
///      descriptor that you have to LocalFree yourself)
///   2. Call LookupAccountSidW to translate the SID into "DOMAIN\username"
///
/// On Linux this is literally just `stat(path).st_uid`. One number. One call.
/// But sure, Microsoft, let's involve security descriptors and SID lookups
/// for "who created this text file."
fn get_file_owner(path: &str) -> anyhow::Result<String> {
    let budget = Budget::new(None)?;
    let absolute = std::path::absolute(path)?;
    let pinned = PinnedPath::new(path_string(&absolute)?, &budget)?;
    let file = pinned.open(READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0, None)?;
    let snapshot = security_snapshot(&file)?;
    let owner = sid_identity(snapshot.owner)?;
    Ok(owner.account.unwrap_or(owner.sid))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mcp-fs-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_str().unwrap().to_owned()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            assert!(self
                .0
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("mcp-fs-test-"));
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn read_value(path: &str, encoding: FileEncoding) -> serde_json::Value {
        serde_json::from_str(
            &read(FsReadInput {
                path: path.to_owned(),
                encoding,
                max_bytes: None,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap()
    }

    fn create_input(path: &str, data: &str, encoding: FileEncoding) -> FsWriteInput {
        FsWriteInput {
            path: path.to_owned(),
            data: data.to_owned(),
            encoding,
            consistency: FileConsistency::CreateNew,
            metadata: None,
            bom: WriteBom::Preserve,
            expected_revision: None,
            timeout_ms: None,
        }
    }

    fn patch_input(path: &str, revision: &str) -> FsPatchInput {
        FsPatchInput {
            path: path.to_owned(),
            encoding: FileEncoding::Utf8,
            expected_revision: revision.to_owned(),
            consistency: FileConsistency::ConditionalInPlace,
            find: "one".to_owned(),
            replacement: "two".to_owned(),
            expected_matches: 2,
            timeout_ms: None,
        }
    }

    #[test]
    fn encoding_bom_and_binary_roundtrips_are_exact() {
        let fixture = Fixture::new();
        for (index, encoding) in [
            FileEncoding::Utf8,
            FileEncoding::Utf16Le,
            FileEncoding::Utf16Be,
        ]
        .into_iter()
        .enumerate()
        {
            let path = fixture.path(&format!("{index}.txt"));
            let text = "a\u{e9}\u{1f642}\r\n";
            let mut input = create_input(&path, text, encoding);
            input.bom = WriteBom::Add;
            let result: serde_json::Value = serde_json::from_str(&write(input).unwrap()).unwrap();
            assert_eq!(result["outcome"], "completed", "{result}");
            let read = read_value(&path, encoding);
            assert_eq!(read["data"], text);
            assert_eq!(read["bom"], true);
            assert_eq!(read["revision"], result["revision"]);
        }
        let path = fixture.path("bytes.bin");
        let binary = [0, 1, 2, 3, 255];
        write(create_input(
            &path,
            &STANDARD.encode(binary),
            FileEncoding::Base64,
        ))
        .unwrap();
        let read = read_value(&path, FileEncoding::Base64);
        assert_eq!(
            STANDARD.decode(read["data"].as_str().unwrap()).unwrap(),
            binary
        );
        assert!(decode(b"\xff\xfea\0", FileEncoding::Utf8).is_err());
        assert!(decode(&[0], FileEncoding::Utf16Le).is_err());
        assert!(decode(&[0, 0xd8], FileEncoding::Utf16Le).is_err());
        assert!(encode("%%%", FileEncoding::Base64, WriteBom::Preserve, false).is_err());
        assert!(encode("AA==", FileEncoding::Base64, WriteBom::Add, false).is_err());
    }

    #[test]
    fn revision_and_match_conflicts_leave_contents_unchanged() {
        let fixture = Fixture::new();
        let path = fixture.path("patch.txt");
        write(create_input(&path, "one one", FileEncoding::Utf8)).unwrap();
        let before = read_value(&path, FileEncoding::Utf8);
        let result: serde_json::Value = serde_json::from_str(
            &patch(patch_input(&path, before["revision"].as_str().unwrap())).unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        let after = read_value(&path, FileEncoding::Utf8);
        assert_eq!(after["data"], "two two");
        assert_eq!(after["identity"], before["identity"]);
        assert_eq!(after["revision"], result["revision"]);
        assert_ne!(after["revision"], before["revision"]);
        assert!(patch(patch_input(&path, before["revision"].as_str().unwrap())).is_err());
        let mut mismatch = patch_input(&path, after["revision"].as_str().unwrap());
        mismatch.find = "two".to_owned();
        mismatch.expected_matches = 1;
        assert!(patch(mismatch).is_err());
        assert!(write(create_input(&path, "replacement", FileEncoding::Utf8)).is_err());
        assert_eq!(read_value(&path, FileEncoding::Utf8)["data"], "two two");
    }

    #[test]
    fn replaced_identity_rejects_same_contents() {
        let fixture = Fixture::new();
        let path = fixture.path("identity.txt");
        write(create_input(&path, "one one", FileEncoding::Utf8)).unwrap();
        let original = read_value(&path, FileEncoding::Utf8);
        std::fs::rename(&path, fixture.path("old.txt")).unwrap();
        std::fs::write(&path, "one one").unwrap();
        assert_ne!(
            read_value(&path, FileEncoding::Utf8)["identity"],
            original["identity"]
        );
        assert!(patch(patch_input(&path, original["revision"].as_str().unwrap())).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one one");
    }

    #[test]
    fn atomic_publication_uses_new_identity_and_cleans_temporary_files() {
        let fixture = Fixture::new();
        let path = fixture.path("atomic.txt");
        write(create_input(&path, "old", FileEncoding::Utf8)).unwrap();
        let before = read_value(&path, FileEncoding::Utf8);
        let mut input = create_input(&path, "new", FileEncoding::Utf8);
        input.consistency = FileConsistency::AtomicReplace;
        assert!(write(input).is_err());
        let mut input = create_input(&path, "new", FileEncoding::Utf8);
        input.consistency = FileConsistency::AtomicReplace;
        input.metadata = Some(WriteMetadata::DestinationDefaults);
        let result: serde_json::Value = serde_json::from_str(&write(input).unwrap()).unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        let after = read_value(&path, FileEncoding::Utf8);
        assert_ne!(before["identity"], after["identity"]);
        assert_eq!(after["data"], "new");
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }

    #[test]
    fn conditional_write_preserves_security_creation_time_and_bom() {
        let fixture = Fixture::new();
        let path = fixture.path("metadata.txt");
        let mut input = create_input(&path, "original", FileEncoding::Utf16Le);
        input.bom = WriteBom::Add;
        write(input).unwrap();
        let before = read_value(&path, FileEncoding::Utf16Le);
        let before_security: serde_json::Value =
            serde_json::from_str(&security(&path).unwrap()).unwrap();
        let before_creation = {
            let file = File::open(&path).unwrap();
            basic_info(&file).unwrap().CreationTime
        };
        let mut input = create_input(&path, "changed", FileEncoding::Utf16Le);
        input.consistency = FileConsistency::ConditionalInPlace;
        input.expected_revision = Some(before["revision"].as_str().unwrap().to_owned());
        let result: serde_json::Value = serde_json::from_str(&write(input).unwrap()).unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        let after = read_value(&path, FileEncoding::Utf16Le);
        let after_security: serde_json::Value =
            serde_json::from_str(&security(&path).unwrap()).unwrap();
        assert_eq!(before_security["sddl"], after_security["sddl"]);
        assert_eq!(before["identity"], after["identity"]);
        assert_eq!(after["bom"], true);
        assert_eq!(after["data"], "changed");
        assert_eq!(
            basic_info(&File::open(&path).unwrap())
                .unwrap()
                .CreationTime,
            before_creation
        );
    }

    #[test]
    fn copy_and_move_report_partial_batches_and_preserve_metadata() {
        let fixture = Fixture::new();
        let source = fixture.path("source.txt");
        let destination = fixture.path("copy.txt");
        write(create_input(&source, "source", FileEncoding::Utf8)).unwrap();
        let original = read_value(&source, FileEncoding::Utf8);
        let original_basic = basic_info(&File::open(&source).unwrap()).unwrap();
        let result: serde_json::Value = serde_json::from_str(
            &copy(FsCopyInput {
                files: vec![
                    FileTransfer {
                        source: source.clone(),
                        destination: destination.clone(),
                        expected_revision: original["revision"].as_str().unwrap().to_owned(),
                    },
                    FileTransfer {
                        source: fixture.path("missing.txt"),
                        destination: fixture.path("never.txt"),
                        expected_revision: "missing".to_owned(),
                    },
                ],
                security: CopySecurity::DestinationDefaults,
                continue_on_error: true,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "partial");
        assert_eq!(result["completed"], 1);
        assert_eq!(result["results"][1]["accepted"], false);
        let copied = read_value(&destination, FileEncoding::Utf8);
        assert_eq!(copied["data"], "source");
        let copied_basic = basic_info(&File::open(&destination).unwrap()).unwrap();
        assert_eq!(original_basic.CreationTime, copied_basic.CreationTime);
        assert_eq!(original_basic.LastWriteTime, copied_basic.LastWriteTime);
        let moved = fixture.path("moved.txt");
        let result: serde_json::Value = serde_json::from_str(
            &move_files(FsMoveInput {
                files: vec![FileTransfer {
                    source: destination.clone(),
                    destination: moved.clone(),
                    expected_revision: copied["revision"].as_str().unwrap().to_owned(),
                }],
                continue_on_error: false,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        assert!(!Path::new(&destination).exists());
        assert_eq!(
            read_value(&moved, FileEncoding::Utf8)["identity"],
            copied["identity"]
        );
    }

    #[test]
    fn hard_links_are_identity_checked_and_removed_without_target_deletion() {
        let fixture = Fixture::new();
        let source = fixture.path("source.txt");
        let destination = fixture.path("hard.txt");
        write(create_input(&source, "data", FileEncoding::Utf8)).unwrap();
        let original = read_value(&source, FileEncoding::Utf8);
        let result: serde_json::Value = serde_json::from_str(
            &link_create(FsLinkCreateInput {
                path: destination.clone(),
                target: source.clone(),
                kind: LinkKind::Hard,
                expected_target_revision: Some(original["revision"].as_str().unwrap().to_owned()),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        let linked: serde_json::Value =
            serde_json::from_str(&link_inspect(&destination).unwrap()).unwrap();
        assert_eq!(linked["kind"], "hard_link");
        assert_eq!(linked["identity"], original["identity"]);
        assert!(link_remove(FsLinkRemoveInput {
            path: destination.clone(),
            expected_revision: "stale".to_owned()
        })
        .is_err());
        let result: serde_json::Value = serde_json::from_str(
            &link_remove(FsLinkRemoveInput {
                path: destination.clone(),
                expected_revision: linked["revision"].as_str().unwrap().to_owned(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "removed", "{result}");
        assert!(!Path::new(&destination).exists());
        assert_eq!(std::fs::read_to_string(&source).unwrap(), "data");
    }

    #[test]
    fn self_acl_scope_does_not_propagate_to_existing_children() {
        let fixture = Fixture::new();
        let root = fixture.0.to_str().unwrap();
        let child = fixture.path("child.txt");
        std::fs::write(&child, "unchanged").unwrap();
        let before: serde_json::Value = serde_json::from_str(&security(&child).unwrap()).unwrap();
        let result: serde_json::Value = serde_json::from_str(
            &acl_modify(FsAclInput {
                path: root.to_owned(),
                scope: TargetScope::SelfOnly,
                inheritance: DaclInheritance::ProtectCopy,
                mode: AclEdit::Merge,
                entries: Vec::new(),
                max_depth: None,
                max_targets: None,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        let after: serde_json::Value = serde_json::from_str(&security(&child).unwrap()).unwrap();
        assert_eq!(before["sddl"], after["sddl"]);
        let root_security: serde_json::Value =
            serde_json::from_str(&security(root).unwrap()).unwrap();
        assert_eq!(root_security["inheritance_protected"], true);
        let result: serde_json::Value = serde_json::from_str(
            &owner_modify(FsOwnerInput {
                path: child.clone(),
                scope: TargetScope::SelfOnly,
                owner_sid: before["owner"]["sid"].as_str().unwrap().to_owned(),
                max_depth: None,
                max_targets: None,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        assert_eq!(std::fs::read_to_string(child).unwrap(), "unchanged");
    }

    #[test]
    fn scope_limits_report_partial_instead_of_success() {
        let fixture = Fixture::new();
        for name in ["one", "two", "three"] {
            std::fs::write(fixture.path(name), "").unwrap();
        }
        let result: serde_json::Value = serde_json::from_str(
            &acl_modify(FsAclInput {
                path: fixture.0.to_str().unwrap().to_owned(),
                scope: TargetScope::Recursive,
                inheritance: DaclInheritance::ProtectCopy,
                mode: AclEdit::Merge,
                entries: Vec::new(),
                max_depth: None,
                max_targets: Some(1),
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "partial");
        assert_eq!(result["traversal_limited"], true);
    }

    #[test]
    fn numeric_strings_work_and_invalid_flags_lengths_and_paths_fail() {
        let read: FsReadInput = serde_json::from_value(
            json!({"path":"C:\\test", "encoding":"utf8", "max_bytes":"42", "timeout_ms":"10"}),
        )
        .unwrap();
        assert_eq!(read.max_bytes, Some(42));
        let patch: FsPatchInput = serde_json::from_value(json!({
                    "path":"C:\\test", "encoding":"utf8", "expected_revision":"revision", "find":"a", "replacement":"b", "expected_matches":"2",
                })).unwrap();
        assert_eq!(patch.expected_matches, 2);
        for value in [json!(-1), json!("4294967296"), json!(1.5)] {
            assert!(serde_json::from_value::<FsReadInput>(
                json!({"path":"C:\\test", "encoding":"utf8", "max_bytes":value})
            )
            .is_err());
        }
        assert!(Budget::new(Some(0)).is_err());
        assert!(Budget::new(Some(120_001)).is_err());
        assert!(file_path("relative.txt").is_err());
        assert!(file_path("C:\\data\\..\\elsewhere").is_err());
        assert!(file_path("C:\\data:stream").is_err());
        assert!(file_path("\\\\.\\PhysicalDrive0").is_err());
        assert!(validate_ace(&AclEntry {
            sid: "S-1-1-0".to_owned(),
            mode: AceMode::Grant,
            rights: 1,
            inheritance_flags: Some(16)
        })
        .is_err());
        assert!(validate_ace(&AclEntry {
            sid: "S-1-1-0".to_owned(),
            mode: AceMode::Grant,
            rights: 1,
            inheritance_flags: Some(8)
        })
        .is_err());
        assert!(OwnedSid::parse("not-a-sid").is_err());
        assert!(reparse_name(&[0; 8], 20, 8).is_err());
    }

    #[test]
    fn failed_writes_track_only_confirmed_bytes() {
        struct ShortWriter(usize);
        impl Write for ShortWriter {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("injected failure"));
                }
                let count = data.len().min(self.0);
                self.0 -= count;
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut count = WriteProgress::default();
        assert!(write_chunks(
            &mut ShortWriter(3),
            b"abcdef",
            &Budget::new(None).unwrap(),
            &mut count
        )
        .is_err());
        assert_eq!(count.bytes, 3);
        assert!(count.accepted);
    }

    #[test]
    fn oversized_file_is_rejected_before_read_or_write() {
        let fixture = Fixture::new();
        let path = fixture.path("large");
        File::create(&path)
            .unwrap()
            .set_len((MAX_FILE_BYTES + 1) as u64)
            .unwrap();
        assert!(read(FsReadInput {
            path,
            encoding: FileEncoding::Base64,
            max_bytes: Some(MAX_FILE_BYTES as u32),
            timeout_ms: None
        })
        .is_err());
    }

    #[test]
    fn restart_manager_reports_a_bounded_observation_without_shutdown() {
        let fixture = Fixture::new();
        let path = fixture.path("resource");
        std::fs::write(&path, "resource").unwrap();
        let _reader = File::open(&path).unwrap();
        let result: serde_json::Value = serde_json::from_str(&locks(&path).unwrap()).unwrap();
        assert_eq!(result["source"], "windows_restart_manager");
        assert_eq!(result["shutdown_requested"], false);
        assert_eq!(result["complete_handle_inventory"], false);
        for process in result["processes"].as_array().unwrap() {
            assert!(process["process_start_filetime"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .is_ok());
        }
    }

    #[test]
    fn native_acl_merge_revoke_and_empty_replace_are_explicit() {
        let fixture = Fixture::new();
        let path = fixture.path("acl");
        std::fs::write(&path, "data").unwrap();
        let held = open_path(
            Path::new(&path),
            READ_CONTROL.0 | WRITE_DAC.0 | FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
        )
        .unwrap();
        let original = security_snapshot(&held).unwrap();
        let edit = |mode, entries| FsAclInput {
            path: path.clone(),
            scope: TargetScope::SelfOnly,
            inheritance: DaclInheritance::ProtectCopy,
            mode,
            entries,
            max_depth: None,
            max_targets: None,
            timeout_ms: None,
        };
        let result: serde_json::Value = serde_json::from_str(
            &acl_modify(edit(
                AclEdit::Merge,
                vec![AclEntry {
                    sid: "S-1-1-0".to_owned(),
                    mode: AceMode::Deny,
                    rights: FILE_WRITE_DATA.0,
                    inheritance_flags: None,
                }],
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        let inspected: serde_json::Value = serde_json::from_str(&security(&path).unwrap()).unwrap();
        assert!(inspected["aces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|ace| ace["trustee"]["sid"] == "S-1-1-0" && ace["ace_type"] == 1));
        let result: serde_json::Value = serde_json::from_str(
            &acl_modify(edit(
                AclEdit::Merge,
                vec![AclEntry {
                    sid: "S-1-1-0".to_owned(),
                    mode: AceMode::Revoke,
                    rights: 0,
                    inheritance_flags: None,
                }],
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        let result: serde_json::Value =
            serde_json::from_str(&acl_modify(edit(AclEdit::Replace, Vec::new())).unwrap()).unwrap();
        let current = security_snapshot(&held).unwrap();
        unsafe {
            win32_result(SetSecurityInfo(
                handle(&held),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(original.dacl),
                None,
            ))
            .unwrap();
        }
        assert_eq!(result["outcome"], "completed", "{result}");
        assert!(!current.dacl.is_null());
        assert_eq!(unsafe { (*current.dacl).AceCount }, 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "data");
    }

    #[test]
    fn copied_source_dacl_is_protected_from_destination_inheritance() {
        let fixture = Fixture::new();
        let source = fixture.path("source");
        let directory = fixture.path("destination");
        std::fs::write(&source, "private").unwrap();
        std::fs::create_dir(&directory).unwrap();
        let source_acl: serde_json::Value = serde_json::from_str(
            &acl_modify(FsAclInput {
                path: source.clone(),
                scope: TargetScope::SelfOnly,
                inheritance: DaclInheritance::ProtectCopy,
                mode: AclEdit::Merge,
                entries: Vec::new(),
                max_depth: None,
                max_targets: None,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(source_acl["outcome"], "completed");
        let destination_acl: serde_json::Value = serde_json::from_str(
            &acl_modify(FsAclInput {
                path: directory.clone(),
                scope: TargetScope::SelfOnly,
                inheritance: DaclInheritance::ProtectCopy,
                mode: AclEdit::Merge,
                entries: vec![AclEntry {
                    sid: "S-1-1-0".to_owned(),
                    mode: AceMode::Grant,
                    rights: FILE_GENERIC_READ.0,
                    inheritance_flags: Some(3),
                }],
                max_depth: None,
                max_targets: None,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(destination_acl["outcome"], "completed", "{destination_acl}");
        let original = read_value(&source, FileEncoding::Utf8);
        let before: serde_json::Value = serde_json::from_str(&security(&source).unwrap()).unwrap();
        let destination = Path::new(&directory)
            .join("copy")
            .to_str()
            .unwrap()
            .to_owned();
        let result: serde_json::Value = serde_json::from_str(
            &copy(FsCopyInput {
                files: vec![FileTransfer {
                    source,
                    destination: destination.clone(),
                    expected_revision: original["revision"].as_str().unwrap().to_owned(),
                }],
                security: CopySecurity::Source,
                continue_on_error: false,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        let after: serde_json::Value =
            serde_json::from_str(&security(&destination).unwrap()).unwrap();
        assert_eq!(before["sddl"], after["sddl"]);
        assert_eq!(after["inheritance_protected"], true);
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "private");
    }

    #[test]
    fn directory_and_stream_copy_failures_leave_no_destination() {
        let fixture = Fixture::new();
        let source = fixture.path("source");
        let destination = fixture.path("copy");
        std::fs::write(&source, "data").unwrap();
        std::fs::write(format!("{source}:extra"), "extra stream").unwrap();
        let read = read_value(&source, FileEncoding::Utf8);
        let result: serde_json::Value = serde_json::from_str(
            &copy(FsCopyInput {
                files: vec![
                    FileTransfer {
                        source: source.clone(),
                        destination: destination.clone(),
                        expected_revision: read["revision"].as_str().unwrap().to_owned(),
                    },
                    FileTransfer {
                        source: fixture.0.to_str().unwrap().to_owned(),
                        destination: fixture.path("directory-copy"),
                        expected_revision: "ignored".to_owned(),
                    },
                ],
                security: CopySecurity::DestinationDefaults,
                continue_on_error: true,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["outcome"], "partial");
        assert_eq!(result["completed"], 0);
        assert!(!Path::new(&destination).exists());
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }

    #[test]
    fn failed_readonly_copy_cleans_its_temporary_file() {
        let fixture = Fixture::new();
        let source = fixture.path("readonly-source");
        let destination = fixture.path("existing-destination");
        std::fs::write(&source, "source").unwrap();
        std::fs::write(&destination, "unchanged").unwrap();
        let wide = to_wide(&source);
        unsafe {
            SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_ATTRIBUTE_READONLY).unwrap();
        }
        let original = read_value(&source, FileEncoding::Utf8);
        let result = copy(FsCopyInput {
            files: vec![FileTransfer {
                source: source.clone(),
                destination: destination.clone(),
                expected_revision: original["revision"].as_str().unwrap().to_owned(),
            }],
            security: CopySecurity::DestinationDefaults,
            continue_on_error: false,
            timeout_ms: None,
        });
        unsafe {
            SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_ATTRIBUTE_NORMAL).unwrap();
        }
        let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(result["outcome"], "partial");
        assert_eq!(result["completed"], 0);
        assert!(!result["results"][0]["error"]
            .as_str()
            .unwrap()
            .contains("cleanup"));
        assert_eq!(std::fs::read_to_string(destination).unwrap(), "unchanged");
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
    }

    #[test]
    fn symbolic_links_are_not_followed_by_reads_walks_or_acl_changes() {
        let fixture = Fixture::new();
        let outside = Fixture::new();
        let outside_file = outside.path("outside.txt");
        std::fs::write(&outside_file, "outside").unwrap();
        let before = security(&outside_file).unwrap();
        let link = fixture.path("link");
        let result = link_create(FsLinkCreateInput {
            path: link.clone(),
            target: outside.0.to_str().unwrap().to_owned(),
            kind: LinkKind::SymbolicDirectory,
            expected_target_revision: None,
        });
        if let Err(error) = result {
            assert!(
                error
                    .downcast_ref::<windows::core::Error>()
                    .is_some_and(|error| error.code() == ERROR_PRIVILEGE_NOT_HELD.to_hresult()),
                "{error:#}"
            );
            assert!(!Path::new(&link).exists());
            return;
        }
        assert!(read(FsReadInput {
            path: Path::new(&link)
                .join("outside.txt")
                .to_str()
                .unwrap()
                .to_owned(),
            encoding: FileEncoding::Utf8,
            max_bytes: None,
            timeout_ms: None
        })
        .is_err());
        let root = fixture.0.to_str().unwrap();
        let list: serde_json::Value =
            serde_json::from_str(&list(root, true, true).unwrap()).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        let searched: serde_json::Value =
            serde_json::from_str(&search(root, "*.txt", 10).unwrap()).unwrap();
        assert!(searched.as_array().unwrap().is_empty());
        let acl: serde_json::Value = serde_json::from_str(
            &acl_modify(FsAclInput {
                path: root.to_owned(),
                scope: TargetScope::Recursive,
                inheritance: DaclInheritance::ProtectCopy,
                mode: AclEdit::Merge,
                entries: Vec::new(),
                max_depth: None,
                max_targets: None,
                timeout_ms: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(acl["outcome"], "partial");
        assert_eq!(security(&outside_file).unwrap(), before);
        let inspected: serde_json::Value =
            serde_json::from_str(&link_inspect(&link).unwrap()).unwrap();
        let removed: serde_json::Value = serde_json::from_str(
            &link_remove(FsLinkRemoveInput {
                path: link,
                expected_revision: inspected["revision"].as_str().unwrap().to_owned(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(removed["outcome"], "removed", "{removed}");
        assert_eq!(std::fs::read_to_string(&outside_file).unwrap(), "outside");
    }

    #[test]
    fn conditional_preconditions_cannot_be_silently_relaxed_to_atomic_replace() {
        let fixture = Fixture::new();
        let path = fixture.path("file");
        write(create_input(&path, "one one", FileEncoding::Utf8)).unwrap();
        let read = read_value(&path, FileEncoding::Utf8);
        let mut input = patch_input(&path, read["revision"].as_str().unwrap());
        input.consistency = FileConsistency::AtomicReplace;
        assert!(patch(input).is_err());
        let mut input = create_input(&path, "unexpected", FileEncoding::Utf8);
        input.consistency = FileConsistency::AtomicReplace;
        input.metadata = Some(WriteMetadata::DestinationDefaults);
        input.expected_revision = Some(read["revision"].as_str().unwrap().to_owned());
        assert!(write(input).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one one");
        assert!(serde_json::from_value::<FsWriteInput>(json!({
            "path": path, "data": "unexpected", "encoding": "utf8",
            "consistency": "conditional_in_place", "expected_revision": read["revision"], "atomic": true,
        })).is_err());
        assert!(serde_json::from_value::<FsAclInput>(json!({
            "path": path, "scope": "self", "inheritance": "preserve", "mode": "replace",
            "entries": [], "sacl": true,
        }))
        .is_err());
    }

    #[test]
    fn explicit_transaction_preserves_identity_and_commits_contents() {
        let fixture = Fixture::new();
        let path = fixture.path("transaction");
        write(create_input(&path, "one one", FileEncoding::Utf8)).unwrap();
        let original = read_value(&path, FileEncoding::Utf8);
        let mut input = patch_input(&path, original["revision"].as_str().unwrap());
        input.consistency = FileConsistency::Transactional;
        let result: serde_json::Value = serde_json::from_str(&patch(input).unwrap()).unwrap();
        assert_eq!(result["outcome"], "completed", "{result}");
        assert_eq!(result["atomicity"], "explicit_ntfs_transaction");
        let after = read_value(&path, FileEncoding::Utf8);
        assert_eq!(after["identity"], original["identity"]);
        assert_eq!(after["data"], "two two");
    }
}

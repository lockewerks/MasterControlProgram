use std::{
    fs::File,
    io::{Read, Write},
    os::windows::{ffi::OsStrExt, io::OwnedHandle},
    path::{Component, Path, PathBuf, Prefix},
    ptr,
};

use anyhow::{bail, Context};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, HANDLE, HLOCAL},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACL,
            DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, LABEL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
            SE_DACL_PROTECTED, SYSTEM_MANDATORY_LABEL_ACE,
        },
        Storage::FileSystem::{
            CreateDirectoryW, CreateFileW, FileDispositionInfo, GetDriveTypeW,
            GetFileInformationByHandle, MoveFileExW, SetFileInformationByHandle,
            BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL,
        },
        System::{
            Com::CoTaskMemFree,
            SystemServices::{
                SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_MANDATORY_LABEL_NO_READ_UP,
                SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            },
            WindowsProgramming::{DRIVE_NO_ROOT_DIR, DRIVE_REMOTE, DRIVE_UNKNOWN},
        },
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath, KF_FLAG_DEFAULT},
    },
};

use super::{own, raw, sid_string, TokenContext};

pub(crate) fn validate_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "host name must contain 1-64 ASCII letters, digits, underscores or hyphens"
    );
    Ok(())
}

fn checkpoint_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        name.len() <= 96
            && !name.is_empty()
            && name != "."
            && name != ".."
            && !name.starts_with('.')
            && !name.ends_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid checkpoint filename"
    );
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    anyhow::ensure!(
        !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            && !(stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9')),
        "checkpoint filename names a Windows device"
    );
    Ok(())
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn validate_local_path(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.is_absolute() && !path.as_os_str().encode_wide().any(|value| value == 0),
        "local state path must be absolute and contain no NUL"
    );
    let drive = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => bail!("local state cannot use a UNC or device namespace path"),
        },
        _ => bail!("local state requires an absolute drive path"),
    };
    let root = crate::win32::to_wide(&format!("{}:\\", char::from(drive)));
    let kind = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
    anyhow::ensure!(
        !matches!(kind, DRIVE_NO_ROOT_DIR | DRIVE_UNKNOWN | DRIVE_REMOTE),
        "local state requires an available local drive, not a network mapping"
    );
    Ok(())
}

fn state_root(base: &Path, name: &str, token: &TokenContext) -> PathBuf {
    base.join(format!("{name}-{}", token.integrity_rid))
}

pub(crate) struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// The allocation is immutable after construction and LocalFree accepts it on any thread.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

impl SecurityDescriptor {
    pub(crate) fn owner_only(sid: &str, inheritable: bool) -> anyhow::Result<Self> {
        Self::build(sid, inheritable, None)
    }

    fn for_storage(token: &TokenContext) -> anyhow::Result<Self> {
        Self::build(&token.user_sid, true, Some(token.integrity_rid))
    }

    fn build(sid: &str, inheritable: bool, integrity: Option<u32>) -> anyhow::Result<Self> {
        let inheritance = if inheritable { "OICI" } else { "" };
        // A protected SACL would require SeSecurityPrivilege even for a label-only descriptor.
        let label = integrity
            .map(|rid| format!("S:(ML;{inheritance};NWNR;;;S-1-16-{rid})"))
            .unwrap_or_default();
        let sddl = crate::win32::to_wide(&format!("O:{sid}D:P(A;{inheritance};GA;;;{sid}){label}"));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )?;
        }
        Ok(Self(descriptor))
    }

    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: false.into(),
        }
    }
}

pub(crate) fn verify_owner_only(handle: HANDLE, expected_sid: &str) -> anyhow::Result<()> {
    let mut owner = PSID::default();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
        .ok()
        .context("read state owner and DACL")?;
    }
    let _allocation = SecurityDescriptor(descriptor);
    anyhow::ensure!(
        sid_string(owner)? == expected_sid,
        "local state owner SID does not match"
    );
    let mut control = 0;
    let mut revision = 0;
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision)? };
    anyhow::ensure!(
        control & SE_DACL_PROTECTED.0 != 0 && !acl.is_null(),
        "local state requires a protected, non-null owner-only DACL"
    );
    unsafe {
        anyhow::ensure!(
            (*acl).AceCount == 1,
            "local state DACL has unexpected access entries"
        );
        let mut ace = ptr::null_mut();
        GetAce(acl, 0, &mut ace)?;
        let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
        anyhow::ensure!(
            ace.Header.AceType == 0,
            "local state requires an owner allow ACE"
        );
        let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
        anyhow::ensure!(
            sid_string(sid)? == expected_sid,
            "local state DACL grants another SID"
        );
        anyhow::ensure!(
            ace.Mask & 0x001f01ff == 0x001f01ff || ace.Mask & 0x10000000 != 0,
            "local state owner lacks full access"
        );
    }
    Ok(())
}

fn verify_integrity(handle: HANDLE, expected_rid: u32) -> anyhow::Result<()> {
    let mut sacl: *mut ACL = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(&mut sacl),
            Some(&mut descriptor),
        )
        .ok()
        .context("read state mandatory integrity label")?;
    }
    let _allocation = SecurityDescriptor(descriptor);
    anyhow::ensure!(
        !sacl.is_null(),
        "local state has no explicit integrity protection"
    );
    let mut found = false;
    unsafe {
        for index in 0..(*sacl).AceCount {
            let mut ace = ptr::null_mut();
            GetAce(sacl, u32::from(index), &mut ace)?;
            let ace = &*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>();
            if u32::from(ace.Header.AceType) != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
                continue;
            }
            let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
            let required = SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
            anyhow::ensure!(
                sid_string(sid)? == format!("S-1-16-{expected_rid}")
                    && ace.Mask & required == required
                    && u32::from(ace.Header.AceFlags) & INHERIT_ONLY_ACE.0 == 0,
                "local state integrity does not match the current execution context"
            );
            found = true;
        }
    }
    anyhow::ensure!(found, "local state lacks a mandatory integrity label");
    Ok(())
}

pub(crate) struct StateDirectory {
    path: PathBuf,
    sid: String,
    integrity_rid: u32,
    descriptor: SecurityDescriptor,
    _handles: Vec<OwnedHandle>,
}

impl StateDirectory {
    pub(crate) fn host(token: &TokenContext, name: &str) -> anyhow::Result<Self> {
        validate_name(name)?;
        Self::scoped(token, "MasterControlProgram-hosts", name)
    }

    pub(crate) fn recovery(token: &TokenContext, scope: &str) -> anyhow::Result<Self> {
        validate_name(scope)?;
        Self::scoped(token, "MasterControlProgram-recovery", scope)
    }

    fn scoped(token: &TokenContext, root_name: &str, scope: &str) -> anyhow::Result<Self> {
        let native_path =
            unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None)? };
        let local = unsafe { native_path.to_string() };
        unsafe { CoTaskMemFree(Some(native_path.0.cast())) };
        let root = state_root(Path::new(&local?), root_name, token);
        let descriptor = SecurityDescriptor::for_storage(token)?;
        let parent = open_directory(&root, &descriptor, token)?;
        let path = root.join(scope);
        let directory = open_directory(&path, &descriptor, token)?;
        Ok(Self {
            path,
            sid: token.user_sid.clone(),
            integrity_rid: token.integrity_rid,
            descriptor,
            _handles: vec![parent, directory],
        })
    }

    pub(crate) fn at(token: &TokenContext, path: &Path) -> anyhow::Result<Self> {
        let descriptor = SecurityDescriptor::for_storage(token)?;
        let directory = open_directory(path, &descriptor, token)?;
        Ok(Self {
            path: path.into(),
            sid: token.user_sid.clone(),
            integrity_rid: token.integrity_rid,
            descriptor,
            _handles: vec![directory],
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn lock_for_host(mut self) -> anyhow::Result<Self> {
        let path = wide(&self.path.join(".host-lock"));
        let attributes = self.descriptor.attributes();
        let handle = unsafe {
            own(CreateFileW(
                PCWSTR(path.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0,
                Default::default(),
                Some(&attributes),
                OPEN_ALWAYS,
                FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            ).context("acquire exclusive host history lease; another host may be using this state directory")?)
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(raw(&handle), &mut info)? };
        anyhow::ensure!(
            info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT.0 | FILE_ATTRIBUTE_DIRECTORY.0)
                == 0,
            "host history lease is not an ordinary file"
        );
        verify_owner_only(raw(&handle), &self.sid)?;
        verify_integrity(raw(&handle), self.integrity_rid)?;
        self._handles.push(handle);
        Ok(self)
    }

    pub(crate) fn read(&self, name: &str, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        checkpoint_name(name)?;
        let path = wide(&self.path.join(name));
        let opened = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                FILE_GENERIC_READ.0 | READ_CONTROL.0,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        };
        let handle = match opened {
            Ok(handle) => unsafe { own(handle) },
            Err(error) if error.code() == ERROR_FILE_NOT_FOUND.to_hresult() => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(raw(&handle), &mut info)? };
        anyhow::ensure!(
            info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT.0 | FILE_ATTRIBUTE_DIRECTORY.0)
                == 0,
            "checkpoint is not an ordinary file"
        );
        verify_owner_only(raw(&handle), &self.sid)?;
        verify_integrity(raw(&handle), self.integrity_rid)?;
        let length = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
        anyhow::ensure!(
            length <= max_bytes as u64,
            "checkpoint exceeds {max_bytes} bytes"
        );
        let mut data = Vec::with_capacity(length as usize);
        File::from(handle)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut data)?;
        anyhow::ensure!(
            data.len() <= max_bytes,
            "checkpoint grew beyond its size limit"
        );
        Ok(Some(data))
    }

    pub(crate) fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        anyhow::ensure!(
            prefix.len() <= 96
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "invalid checkpoint prefix"
        );
        let mut names = Vec::new();
        for (index, entry) in std::fs::read_dir(&self.path)?.enumerate() {
            anyhow::ensure!(index < 4096, "checkpoint directory exceeds 4096 entries");
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("checkpoint name is not Unicode"))?;
            if name.starts_with('.') || !name.starts_with(prefix) {
                continue;
            }
            checkpoint_name(&name)?;
            anyhow::ensure!(
                entry.file_type()?.is_file(),
                "checkpoint entry is not an ordinary file: {name}"
            );
            names.push(name);
        }
        names.sort_unstable();
        Ok(names)
    }

    pub(crate) fn remove(&self, name: &str) -> anyhow::Result<bool> {
        checkpoint_name(name)?;
        let path = wide(&self.path.join(name));
        let opened = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                DELETE.0 | READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        };
        let handle = match opened {
            Ok(handle) => unsafe { own(handle) },
            Err(error) if error.code() == ERROR_FILE_NOT_FOUND.to_hresult() => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(raw(&handle), &mut info)? };
        anyhow::ensure!(
            info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT.0 | FILE_ATTRIBUTE_DIRECTORY.0)
                == 0,
            "checkpoint is not an ordinary file"
        );
        verify_owner_only(raw(&handle), &self.sid)?;
        verify_integrity(raw(&handle), self.integrity_rid)?;
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        unsafe {
            SetFileInformationByHandle(
                raw(&handle),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )?;
        }
        Ok(true)
    }

    pub(crate) fn write(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        checkpoint_name(name)?;
        let destination = self.path.join(name);
        let temporary = self.path.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let temp_wide = wide(&temporary);
        let attributes = self.descriptor.attributes();
        let handle = unsafe {
            own(CreateFileW(
                PCWSTR(temp_wide.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ,
                Some(&attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .context("create protected checkpoint temporary file")?)
        };
        let write_result = (|| -> anyhow::Result<()> {
            let mut file = File::from(handle);
            file.write_all(data)?;
            file.sync_all()?;
            drop(file);
            let dest_wide = wide(&destination);
            unsafe {
                MoveFileExW(
                    PCWSTR(temp_wide.as_ptr()),
                    PCWSTR(dest_wide.as_ptr()),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )?;
            }
            Ok(())
        })();
        if write_result.is_err() {
            if let Err(error) = std::fs::remove_file(&temporary) {
                tracing::error!(path = %temporary.display(), %error, "failed to remove checkpoint temporary file");
            }
        }
        write_result.with_context(|| format!("write checkpoint {}", destination.display()))
    }
}

fn open_directory(
    path: &Path,
    descriptor: &SecurityDescriptor,
    token: &TokenContext,
) -> anyhow::Result<OwnedHandle> {
    validate_local_path(path)?;
    let path_wide = wide(path);
    let attributes = descriptor.attributes();
    if let Err(error) = unsafe { CreateDirectoryW(PCWSTR(path_wide.as_ptr()), Some(&attributes)) } {
        if error.code() != ERROR_ALREADY_EXISTS.to_hresult() {
            return Err(error)
                .with_context(|| format!("create protected state directory {}", path.display()));
        }
    }
    let directory = unsafe {
        own(CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )?)
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(raw(&directory), &mut info)? };
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
    {
        bail!(
            "local state directory is not an ordinary directory: {}",
            path.display()
        );
    }
    verify_owner_only(raw(&directory), &token.user_sid)?;
    verify_integrity(raw(&directory), token.integrity_rid)?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_storage_round_trip_and_validation() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!("mcp-host-storage-{}", uuid::Uuid::new_v4()));
        let context = super::super::PersistenceContext::test_host(&path)?;
        assert_eq!(context.read_checkpoint("state.json", 1024)?, None);
        context.write_checkpoint("state.json", b"first")?;
        context.write_checkpoint("state.json", b"second")?;
        assert_eq!(
            context.read_checkpoint("state.json", 1024)?.unwrap(),
            b"second"
        );
        assert!(context.read_checkpoint("state.json", 2).is_err());
        assert!(context.write_checkpoint("..\\escape", b"no").is_err());
        drop(context);
        std::fs::remove_file(path.join("state.json"))?;
        std::fs::remove_dir(&path)?;
        Ok(())
    }

    #[test]
    fn endpoint_and_checkpoint_names_cannot_escape() {
        for name in [
            "",
            ".",
            "..",
            "a\\b",
            "a/b",
            "\\\\remote\\pipe",
            "x:",
            "x\0",
            "x ",
        ] {
            assert!(validate_name(name).is_err());
        }
        assert!(validate_name("build_42-dev").is_ok());
        assert!(checkpoint_name("events.json").is_ok());
        assert!(checkpoint_name("state.").is_err());
        assert!(checkpoint_name("NUL.json").is_err());
        assert!(checkpoint_name("com1").is_err());
    }

    #[test]
    fn existing_inherited_directory_is_rejected_without_acl_changes() -> anyhow::Result<()> {
        let path =
            std::env::temp_dir().join(format!("mcp-insecure-state-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path)?;
        let result = super::super::PersistenceContext::test_host(&path);
        assert!(result.is_err());
        std::fs::remove_dir(path)?;
        Ok(())
    }

    #[test]
    fn recovery_entries_are_separate_bounded_and_removed_by_handle() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!("mcp-recovery-{}", uuid::Uuid::new_v4()));
        let store = super::super::RecoveryStore::at(&path)?;
        assert_eq!(store.state_directory(), path);
        store.write_checkpoint("trace-a.json", b"first")?;
        store.write_checkpoint("trace-b.json", b"second")?;
        assert_eq!(store.list("trace-")?, vec!["trace-a.json", "trace-b.json"]);
        assert_eq!(
            store.read_checkpoint("trace-a.json", 32)?.unwrap(),
            b"first"
        );
        assert!(store.read_checkpoint("trace-b.json", 1).is_err());
        assert!(store.list("..\\").is_err());
        assert!(store.remove_checkpoint("trace-a.json")?);
        assert!(!store.remove_checkpoint("trace-a.json")?);
        assert_eq!(store.list("trace-")?, vec!["trace-b.json"]);
        assert!(store.remove_checkpoint("trace-b.json")?);
        drop(store);
        std::fs::remove_dir(path)?;
        Ok(())
    }

    #[test]
    fn host_history_scope_is_stable_and_exclusively_leased() -> anyhow::Result<()> {
        let token = TokenContext::current()?;
        let mut next_logon = token.clone();
        next_logon.session_id += 1;
        next_logon.logon_id.push('1');
        let base = Path::new(r"C:\fixture");
        let root = state_root(base, "MasterControlProgram-hosts", &token);
        assert_eq!(
            root,
            state_root(base, "MasterControlProgram-hosts", &next_logon)
        );
        assert_ne!(
            token.endpoint_key("build")?,
            next_logon.endpoint_key("build")?
        );
        next_logon.integrity_rid += 4096;
        assert_ne!(
            root,
            state_root(base, "MasterControlProgram-hosts", &next_logon)
        );
        assert!(validate_local_path(Path::new(r"\\server\share\state")).is_err());
        assert!(validate_local_path(Path::new(r"\\?\UNC\server\share\state")).is_err());
        assert!(validate_local_path(Path::new(r"\\.\pipe\state")).is_err());

        let path = std::env::temp_dir().join(format!("mcp-history-lease-{}", uuid::Uuid::new_v4()));
        let first = super::super::PersistenceContext::test_host(&path)?;
        first.write_checkpoint("state.json", b"retained")?;
        assert!(super::super::PersistenceContext::test_host(&path).is_err());
        drop(first);
        let second = super::super::PersistenceContext::test_host(&path)?;
        assert_eq!(
            second.read_checkpoint("state.json", 32)?.unwrap(),
            b"retained"
        );
        drop(second);
        std::fs::remove_file(path.join("state.json"))?;
        std::fs::remove_dir(path)?;
        Ok(())
    }

    #[test]
    fn lower_integrity_cannot_read_write_or_remove_recovery_records() -> anyhow::Result<()> {
        use windows::Win32::{
            Security::{
                Authorization::ConvertStringSidToSidW, CreateRestrictedToken, GetLengthSid,
                ImpersonateLoggedOnUser, RevertToSelf, SetTokenInformation, TokenIntegrityLevel,
                DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_DUPLICATE,
                TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
            },
            System::{
                SystemServices::SE_GROUP_INTEGRITY,
                Threading::{GetCurrentProcess, OpenProcessToken},
            },
        };
        let token = TokenContext::current()?;
        if token.integrity_rid <= 4096 {
            eprintln!(
                "Lower-integrity isolation probe unavailable: controller already has low integrity"
            );
            return Ok(());
        }
        let path = std::env::temp_dir().join(format!("mcp-integrity-{}", uuid::Uuid::new_v4()));
        let store = super::super::RecoveryStore::at(&path)?;
        store.write_checkpoint("trace.json", b"owned")?;
        let mut primary = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT,
                &mut primary,
            )?;
        }
        let primary = unsafe { own(primary) };
        let mut restricted = HANDLE::default();
        unsafe {
            CreateRestrictedToken(
                raw(&primary),
                DISABLE_MAX_PRIVILEGE,
                None,
                None,
                None,
                &mut restricted,
            )?
        };
        let restricted = unsafe { own(restricted) };
        let mut sid = PSID::default();
        unsafe { ConvertStringSidToSidW(windows::core::w!("S-1-16-4096"), &mut sid)? };
        let length =
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() + unsafe { GetLengthSid(sid) } as usize;
        let mut buffer = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
        unsafe {
            *buffer.as_mut_ptr().cast::<TOKEN_MANDATORY_LABEL>() = TOKEN_MANDATORY_LABEL {
                Label: SID_AND_ATTRIBUTES {
                    Sid: sid,
                    Attributes: SE_GROUP_INTEGRITY as u32,
                },
            };
        }
        let configured = unsafe {
            SetTokenInformation(
                raw(&restricted),
                TokenIntegrityLevel,
                buffer.as_ptr().cast(),
                length as u32,
            )
        };
        unsafe { LocalFree(Some(HLOCAL(sid.0))) };
        configured?;
        unsafe { ImpersonateLoggedOnUser(raw(&restricted))? };
        let read = std::fs::read(path.join("trace.json"));
        let write = std::fs::write(path.join("trace.json"), b"spoofed");
        let create = std::fs::write(path.join("forged.json"), b"spoofed");
        let remove = std::fs::remove_file(path.join("trace.json"));
        let list = std::fs::read_dir(&path);
        if let Err(error) = unsafe { RevertToSelf() } {
            eprintln!("cannot revert integrity-test impersonation: {error}");
            std::process::abort();
        }
        assert!(
            read.is_err() && write.is_err() && create.is_err() && remove.is_err() && list.is_err()
        );
        assert_eq!(store.read_checkpoint("trace.json", 32)?.unwrap(), b"owned");
        store.remove_checkpoint("trace.json")?;
        drop(store);
        std::fs::remove_dir(path)?;
        Ok(())
    }
}

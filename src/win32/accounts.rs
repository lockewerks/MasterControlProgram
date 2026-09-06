use super::{from_wide, pretty, to_wide};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::mem::{align_of, size_of};
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use windows::core::{Error as WindowsError, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NONE_MAPPED, FILETIME, HLOCAL,
    SYSTEMTIME,
};
use windows::Win32::NetworkManagement::NetManagement::*;
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{
    CopySid, EqualSid, GetLengthSid, IsValidSid, LookupAccountNameW, LookupAccountSidW,
    SidTypeAlias, SidTypeComputer, SidTypeDomain, SidTypeGroup, SidTypeUser, SidTypeWellKnownGroup,
    PSID, SECURITY_MAX_SID_SIZE, SID_NAME_USE,
};
use windows::Win32::System::Time::FileTimeToSystemTime;

const PAGE_BYTES: u32 = 64 * 1024;
const MAX_ENUM_ENTRIES: usize = 100_000;
const MAX_ENUM_PAGES: usize = 4096;
const MAX_LOOKUP_CHARS: usize = 32_768;
const LOOKUP_ATTEMPTS: usize = 4;
const SID_WORDS: usize = SECURITY_MAX_SID_SIZE as usize / size_of::<u32>();
const CREATE_NAME_CHARS: usize = 20;
const TIME_FOREVER: u32 = u32::MAX;

fn net_result(status: u32, operation: &str) -> Result<()> {
    if status != NERR_Success {
        let error = WindowsError::from_hresult(HRESULT::from_win32(status));
        return Err(anyhow::Error::new(error))
            .with_context(|| format!("{operation} failed (Win32 {status})"));
    }
    Ok(())
}

fn has_win32_code(error: &anyhow::Error, code: u32) -> bool {
    error
        .downcast_ref::<WindowsError>()
        .is_some_and(|error| error.code() == HRESULT::from_win32(code))
}

#[derive(Default)]
struct NetBuffer(*mut u8);

impl NetBuffer {
    // The requested type must match the information level used to allocate this buffer.
    unsafe fn entries<T>(&self, count: u32) -> Result<&[T]> {
        if count == 0 {
            return Ok(&[]);
        }
        if self.0.is_null() || !(self.0 as usize).is_multiple_of(align_of::<T>()) {
            bail!("NetAPI returned a missing or misaligned information buffer");
        }
        let mut bytes = 0;
        net_result(
            NetApiBufferSize(self.0.cast(), &mut bytes),
            "NetApiBufferSize",
        )?;
        let required = (count as usize)
            .checked_mul(size_of::<T>())
            .context("NetAPI information buffer size overflow")?;
        if required > bytes as usize || required > isize::MAX as usize {
            bail!("NetAPI returned an incomplete information buffer");
        }
        Ok(std::slice::from_raw_parts(self.0.cast(), count as usize))
    }
}

impl Drop for NetBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = NetApiBufferFree(Some(self.0.cast()));
            }
        }
    }
}

struct LocalWide(PWSTR);

impl Drop for LocalWide {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0.cast())));
            }
        }
    }
}

struct LocalSid(PSID);

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

#[derive(Clone)]
struct Sid([u32; SID_WORDS]);

impl Sid {
    fn as_psid(&self) -> PSID {
        PSID(self.0.as_ptr().cast_mut().cast())
    }

    unsafe fn copy(source: PSID) -> Result<Self> {
        if source.0.is_null() || !IsValidSid(source).as_bool() {
            bail!("Windows returned an invalid account SID");
        }
        let length = GetLengthSid(source);
        if length > SECURITY_MAX_SID_SIZE {
            bail!("Windows returned an oversized account SID");
        }
        let mut sid = Self([0; SID_WORDS]);
        CopySid(
            SECURITY_MAX_SID_SIZE,
            PSID(sid.0.as_mut_ptr().cast()),
            source,
        )
        .context("CopySid")?;
        Ok(sid)
    }

    fn from_text(value: &str) -> Result<Self> {
        let wide = to_wide(value);
        let mut source = LocalSid(PSID::default());
        unsafe {
            ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut source.0)
                .context("ConvertStringSidToSidW")?;
            Self::copy(source.0)
        }
    }

    fn text(&self) -> Result<String> {
        let mut text = LocalWide(PWSTR::null());
        unsafe {
            ConvertSidToStringSidW(self.as_psid(), &mut text.0)
                .context("ConvertSidToStringSidW")?;
            Ok(from_wide(text.0 .0))
        }
    }

    fn equals(&self, other: &Self) -> bool {
        unsafe { EqualSid(self.as_psid(), other.as_psid()).is_ok() }
    }
}

#[derive(Default)]
struct EnumerationBudget {
    pages: usize,
    entries: usize,
}

impl EnumerationBudget {
    fn start_page(&mut self, operation: &str) -> Result<()> {
        if self.pages >= MAX_ENUM_PAGES {
            bail!(
                "Partial {operation}: stopped after {} pages and {} entries (page limit {})",
                self.pages,
                self.entries,
                MAX_ENUM_PAGES
            );
        }
        self.pages += 1;
        Ok(())
    }

    fn finish_page(
        &mut self,
        operation: &str,
        status: u32,
        count: u32,
        resume_advanced: bool,
    ) -> Result<bool> {
        let more = status == ERROR_MORE_DATA.0;
        if !more {
            net_result(status, operation).with_context(|| {
                format!(
                    "Partial {operation}: {} entries read before failure",
                    self.entries
                )
            })?;
        }
        if count as usize > MAX_ENUM_ENTRIES - self.entries {
            bail!(
                "Partial {operation}: entry limit {} exceeded after {} entries",
                MAX_ENUM_ENTRIES,
                self.entries
            );
        }
        self.entries += count as usize;
        if more && (count == 0 || !resume_advanced) {
            bail!(
                "Partial {operation}: pagination made no progress after {} entries",
                self.entries
            );
        }
        Ok(more)
    }
}

fn validate_text(value: &str, field: &str, max_chars: usize) -> Result<()> {
    if value.contains('\0') {
        bail!("{field} must not contain a NUL character");
    }
    if value.encode_utf16().count() > max_chars {
        bail!("{field} exceeds the limit of {max_chars} UTF-16 code units");
    }
    Ok(())
}

fn validate_local_name(value: &str, field: &str, max_chars: usize) -> Result<()> {
    validate_text(value, field, max_chars)?;
    if value.trim().is_empty() || value.ends_with('.') {
        bail!("{field} must not be blank or end with a period");
    }
    if value
        .chars()
        .any(|character| character.is_control() || "\"/\\[]:;|=,+*?<>".contains(character))
    {
        bail!("{field} contains a character that Windows does not allow in a local account name");
    }
    Ok(())
}

fn validate_member(value: &str) -> Result<()> {
    validate_text(value, "Member", 1024)?;
    if value.trim().is_empty() {
        bail!("Member must not be blank");
    }
    if let Some((domain, name)) = value.split_once('\\') {
        if domain.is_empty() || name.is_empty() || name.contains('\\') {
            bail!("Member must be a name, DOMAIN\\name, UPN, or SID, not a remote server path");
        }
    }
    Ok(())
}

fn flags_with_enabled(flags: u32, enabled: Option<bool>) -> u32 {
    match enabled {
        Some(true) => flags & !UF_ACCOUNTDISABLE.0,
        Some(false) => flags | UF_ACCOUNTDISABLE.0,
        None => flags,
    }
}

struct PasswordBuffer(Vec<u16>);

impl PasswordBuffer {
    fn new(password: &str) -> Result<Self> {
        validate_text(password, "Password", PWLEN as usize)?;
        // Allocate once so reallocation cannot leave an unwiped password behind.
        let mut buffer = Vec::with_capacity(password.encode_utf16().count() + 1);
        buffer.extend(password.encode_utf16());
        buffer.push(0);
        Ok(Self(buffer))
    }

    fn clear(&mut self) {
        for character in &mut self.0 {
            unsafe { ptr::write_volatile(character, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for PasswordBuffer {
    fn drop(&mut self) {
        self.clear();
    }
}

fn now_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("The system clock is earlier than the Unix epoch")?
        .as_secs())
}

fn timestamp(seconds: u64) -> Result<String> {
    let ticks = seconds
        .checked_add(11_644_473_600)
        .and_then(|seconds| seconds.checked_mul(10_000_000))
        .context("Account timestamp is outside the Windows FILETIME range")?;
    let filetime = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut time = SYSTEMTIME::default();
    unsafe { FileTimeToSystemTime(&filetime, &mut time).context("FileTimeToSystemTime")? };
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
    ))
}

struct User {
    name: String,
    full_name: String,
    description: String,
    flags: u32,
    last_logon: u32,
    password_age: u32,
    password_expired: bool,
    observed_at: u64,
    sid: Option<Sid>,
}

impl User {
    fn password_last_set(&self) -> Option<u64> {
        // NetUser reports elapsed seconds, not the original last-set FILETIME.
        (self.password_age != TIME_FOREVER)
            .then(|| self.observed_at.checked_sub(self.password_age as u64))
            .flatten()
    }

    fn summary(&self) -> Result<Value> {
        let last_logon = if self.last_logon == 0 {
            None
        } else {
            Some(timestamp(self.last_logon as u64)?)
        };
        let password_last_set = self.password_last_set().map(timestamp).transpose()?;
        let mut value = json!({
            "Name": self.name,
            "FullName": self.full_name,
            "Enabled": self.flags & UF_ACCOUNTDISABLE.0 == 0,
            "LastLogon": last_logon,
            "PasswordRequired": self.flags & UF_PASSWD_NOTREQD.0 == 0,
            "PasswordLastSet": password_last_set,
            "Description": self.description,
        });
        if password_last_set.is_none() {
            value["PasswordLastSetUnavailable"] =
                json!("NetUser did not return a usable password age");
        }
        Ok(value)
    }

    fn modification_summary(&self) -> Value {
        json!({
            "Name": self.name,
            "FullName": self.full_name,
            "Enabled": self.flags & UF_ACCOUNTDISABLE.0 == 0,
            "Description": self.description,
        })
    }
}

fn read_user(name: &str) -> Result<User> {
    validate_local_name(name, "User name", UNLEN as usize)?;
    let wide = to_wide(name);
    let mut buffer = NetBuffer::default();
    unsafe {
        net_result(
            NetUserGetInfo(None, PCWSTR(wide.as_ptr()), 4, &mut buffer.0),
            "NetUserGetInfo(level 4, local)",
        )?;
        let observed_at = now_seconds()?;
        let info = &buffer.entries::<USER_INFO_4>(1)?[0];
        Ok(User {
            name: from_wide(info.usri4_name.0),
            full_name: from_wide(info.usri4_full_name.0),
            description: from_wide(info.usri4_comment.0),
            flags: info.usri4_flags.0,
            last_logon: info.usri4_last_logon,
            password_age: info.usri4_password_age,
            password_expired: info.usri4_password_expired != 0
                || info.usri4_flags.0 & UF_PASSWORD_EXPIRED.0 != 0,
            observed_at,
            sid: Some(Sid::copy(info.usri4_user_sid)?),
        })
    }
}

fn list_users() -> Result<String> {
    let mut budget = EnumerationBudget::default();
    let mut resume = 0;
    let mut users = Vec::new();
    loop {
        budget.start_page("NetUserEnum")?;
        let previous_resume = resume;
        let mut buffer = NetBuffer::default();
        let mut count = 0;
        let mut total = 0;
        let status = unsafe {
            NetUserEnum(
                None,
                2,
                FILTER_NORMAL_ACCOUNT,
                &mut buffer.0,
                PAGE_BYTES,
                &mut count,
                &mut total,
                Some(&mut resume),
            )
        };
        let observed_at = now_seconds()?;
        let more = budget.finish_page("NetUserEnum", status, count, resume != previous_resume)?;
        unsafe {
            for info in buffer.entries::<USER_INFO_2>(count)? {
                let user = User {
                    name: from_wide(info.usri2_name.0),
                    full_name: from_wide(info.usri2_full_name.0),
                    description: from_wide(info.usri2_comment.0),
                    flags: info.usri2_flags.0,
                    last_logon: info.usri2_last_logon,
                    password_age: info.usri2_password_age,
                    password_expired: info.usri2_flags.0 & UF_PASSWORD_EXPIRED.0 != 0,
                    observed_at,
                    sid: None,
                };
                users.push(user.summary()?);
            }
        }
        if !more {
            break;
        }
    }
    sort_names(&mut users);
    Ok(pretty(&json!(users)))
}

fn detail_user(name: &str) -> Result<String> {
    let user = read_user(name)?;
    let sid = user
        .sid
        .as_ref()
        .context("NetUserGetInfo did not supply a SID")?;
    let mut result = user.summary()?;
    result["SID"] = json!(sid.text()?);
    let mut budget = EnumerationBudget::default();
    let mut memberships = Vec::new();
    for group in enumerate_groups(&mut budget)? {
        let members = member_sids(&group.name, &mut budget).with_context(|| {
            format!(
                "Partial user detail: membership in '{}' is unavailable",
                group.name
            )
        })?;
        if members.iter().any(|member| member.equals(sid)) {
            memberships.push(group.name);
        }
    }
    memberships.sort();
    result["Groups"] = json!(memberships);
    result["PasswordExpires"] = Value::Null;
    if user.password_expired {
        result["PasswordExpiresUnavailable"] = json!(
            "Windows reports that the password is expired; NetUser does not expose that expiry timestamp"
        );
    } else if user.flags & UF_DONT_EXPIRE_PASSWD.0 == 0 {
        let mut buffer = NetBuffer::default();
        let max_age = unsafe {
            net_result(
                NetUserModalsGet(None, 0, &mut buffer.0),
                "NetUserModalsGet(level 0, local password policy)",
            )
            .context("Partial user detail: password expiry policy is unavailable")?;
            buffer.entries::<USER_MODALS_INFO_0>(1)?[0].usrmod0_max_passwd_age
        };
        if max_age != TIME_FOREVER {
            if let Some(last_set) = user.password_last_set() {
                result["PasswordExpires"] = json!(timestamp(last_set + max_age as u64)?);
            } else {
                result["PasswordExpiresUnavailable"] =
                    json!("NetUser did not return a usable password age");
            }
        }
    }
    Ok(pretty(&result))
}

fn create_user(input: &crate::server::UserCreateInput) -> Result<String> {
    validate_local_name(&input.name, "User name", CREATE_NAME_CHARS)?;
    let name = to_wide(&input.name);
    let full_name = input.full_name.as_deref().unwrap_or("");
    let description = input.description.as_deref().unwrap_or("");
    validate_text(full_name, "Full name", UNLEN as usize)?;
    validate_text(description, "Description", MAXCOMMENTSZ as usize)?;
    let mut full_name = to_wide(full_name);
    let mut description = to_wide(description);
    let mut parameter = 0;
    let status = {
        let mut password = PasswordBuffer::new(&input.password)?;
        let info = USER_INFO_2 {
            usri2_name: PWSTR(name.as_ptr().cast_mut()),
            usri2_password: PWSTR(password.0.as_mut_ptr()),
            usri2_priv: USER_PRIV_USER,
            usri2_comment: PWSTR(description.as_mut_ptr()),
            usri2_flags: USER_ACCOUNT_FLAGS(
                UF_SCRIPT.0
                    | UF_NORMAL_ACCOUNT
                    | if input.no_password_expiry.unwrap_or(false) {
                        UF_DONT_EXPIRE_PASSWD.0
                    } else {
                        0
                    },
            ),
            usri2_full_name: PWSTR(full_name.as_mut_ptr()),
            usri2_acct_expires: TIME_FOREVER,
            usri2_max_storage: u32::MAX,
            ..Default::default()
        };
        unsafe {
            NetUserAdd(
                None,
                2,
                (&info as *const USER_INFO_2).cast(),
                Some(&mut parameter),
            )
        }
    };
    net_result(status, "NetUserAdd(level 2, local)")
        .with_context(|| format!("Account creation failed; parameter index {parameter}"))?;
    let user = read_user(&input.name)
        .context("Account was created, but reading the resulting account failed")?;
    let sid = user
        .sid
        .as_ref()
        .context("Account was created, but its SID is unavailable")?
        .text()
        .context("Account was created, but formatting its SID failed")?;
    Ok(pretty(&json!({
        "Name": user.name,
        "FullName": user.full_name,
        "Enabled": user.flags & UF_ACCOUNTDISABLE.0 == 0,
        "SID": sid,
    })))
}

fn delete_user(name: &str) -> Result<String> {
    validate_local_name(name, "User name", UNLEN as usize)?;
    let wide = to_wide(name);
    unsafe {
        net_result(NetUserDel(None, PCWSTR(wide.as_ptr())), "NetUserDel(local)")?;
    }
    Ok(pretty(&json!({ "Deleted": name, "Status": "Removed" })))
}

unsafe fn set_user_info<T>(name: PCWSTR, level: u32, info: &T) -> Result<()> {
    let mut parameter = 0;
    net_result(
        NetUserSetInfo(
            None,
            name,
            level,
            (info as *const T).cast(),
            Some(&mut parameter),
        ),
        &format!("NetUserSetInfo(level {level}, local; parameter index {parameter})"),
    )
}

fn modification_error(error: anyhow::Error, applied: &[&str]) -> anyhow::Error {
    error.context(format!(
        "Account modification stopped; fields already applied: {}",
        if applied.is_empty() {
            "none".to_owned()
        } else {
            applied.join(", ")
        }
    ))
}

fn modify_user(input: &crate::server::UserModifyInput) -> Result<String> {
    validate_local_name(&input.name, "User name", UNLEN as usize)?;
    if let Some(value) = &input.full_name {
        validate_text(value, "Full name", UNLEN as usize)?;
    }
    if let Some(value) = &input.description {
        validate_text(value, "Description", MAXCOMMENTSZ as usize)?;
    }
    let original = read_user(&input.name)?;
    let name = to_wide(&original.name);
    let mut applied = Vec::new();
    if let Some(value) = &input.full_name {
        let mut value = to_wide(value);
        let info = USER_INFO_1011 {
            usri1011_full_name: PWSTR(value.as_mut_ptr()),
        };
        unsafe { set_user_info(PCWSTR(name.as_ptr()), 1011, &info) }
            .map_err(|error| modification_error(error, &applied))?;
        applied.push("FullName");
    }
    if let Some(value) = &input.description {
        let mut value = to_wide(value);
        let info = USER_INFO_1007 {
            usri1007_comment: PWSTR(value.as_mut_ptr()),
        };
        unsafe { set_user_info(PCWSTR(name.as_ptr()), 1007, &info) }
            .map_err(|error| modification_error(error, &applied))?;
        applied.push("Description");
    }
    if input.enabled.is_some() {
        // Re-read after the other writes, and change only UF_ACCOUNTDISABLE.
        let current =
            read_user(&original.name).map_err(|error| modification_error(error, &applied))?;
        let flags = flags_with_enabled(current.flags, input.enabled);
        if flags != current.flags {
            let info = USER_INFO_1008 {
                usri1008_flags: USER_ACCOUNT_FLAGS(flags),
            };
            unsafe { set_user_info(PCWSTR(name.as_ptr()), 1008, &info) }
                .map_err(|error| modification_error(error, &applied))?;
            applied.push("Enabled");
        }
    }
    let result = read_user(&original.name)
        .map_err(|error| modification_error(error.context("Account readback failed"), &applied))?;
    Ok(pretty(&result.modification_summary()))
}

struct LocalSam {
    name: String,
    sid: String,
}

impl LocalSam {
    fn read() -> Result<Self> {
        let mut buffer = NetBuffer::default();
        unsafe {
            net_result(
                NetUserModalsGet(None, 2, &mut buffer.0),
                "NetUserModalsGet(level 2, local account domain)",
            )?;
            let info = &buffer.entries::<USER_MODALS_INFO_2>(1)?[0];
            let name = from_wide(info.usrmod2_domain_name.0);
            if name.is_empty() {
                bail!("Windows returned an empty local account domain");
            }
            Ok(Self {
                name,
                sid: Sid::copy(info.usrmod2_domain_id)?.text()?,
            })
        }
    }
}

fn belongs_to_domain(sid: &str, domain_sid: &str) -> bool {
    sid.rsplit_once('-').is_some_and(|(domain, rid)| {
        domain == domain_sid && !rid.is_empty() && rid.parse::<u32>().is_ok()
    })
}

fn is_local_sid(sid: &str, sam: &LocalSam) -> bool {
    belongs_to_domain(sid, &sam.sid) || belongs_to_domain(sid, "S-1-5-32")
}

fn checked_lookup_size(required: u32) -> Result<usize> {
    let required = required as usize;
    if required > MAX_LOOKUP_CHARS {
        bail!("Account lookup exceeded the {MAX_LOOKUP_CHARS}-character buffer limit");
    }
    Ok(required.max(1))
}

fn lookup_name(name: &str) -> Result<(Sid, SID_NAME_USE)> {
    let name = to_wide(name);
    let mut domain = vec![0u16; 257];
    for _ in 0..LOOKUP_ATTEMPTS {
        let mut sid = Sid([0; SID_WORDS]);
        let mut sid_bytes = SECURITY_MAX_SID_SIZE;
        let mut domain_chars = domain.len() as u32;
        let mut usage = SID_NAME_USE::default();
        let result = unsafe {
            LookupAccountNameW(
                None,
                PCWSTR(name.as_ptr()),
                Some(PSID(sid.0.as_mut_ptr().cast())),
                &mut sid_bytes,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_chars,
                &mut usage,
            )
        };
        match result {
            Ok(()) => {
                if sid_bytes > SECURITY_MAX_SID_SIZE
                    || !unsafe { IsValidSid(sid.as_psid()).as_bool() }
                {
                    bail!("LookupAccountNameW returned an invalid SID");
                }
                return Ok((sid, usage));
            }
            Err(error) if error.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                if sid_bytes > SECURITY_MAX_SID_SIZE {
                    bail!("LookupAccountNameW requested an oversized SID");
                }
                domain.resize(checked_lookup_size(domain_chars)?, 0);
            }
            Err(error) => return Err(error).context("LookupAccountNameW"),
        }
    }
    bail!("LookupAccountNameW did not converge after {LOOKUP_ATTEMPTS} attempts")
}

struct AccountName {
    domain: String,
    name: String,
    usage: SID_NAME_USE,
}

impl AccountName {
    fn qualified(&self) -> String {
        if self.domain.is_empty() {
            self.name.clone()
        } else {
            format!("{}\\{}", self.domain, self.name)
        }
    }
}

fn lookup_sid(sid: &Sid) -> Result<AccountName> {
    let mut name = vec![0u16; 257];
    let mut domain = vec![0u16; 257];
    for _ in 0..LOOKUP_ATTEMPTS {
        let mut name_chars = name.len() as u32;
        let mut domain_chars = domain.len() as u32;
        let mut usage = SID_NAME_USE::default();
        let result = unsafe {
            LookupAccountSidW(
                None,
                sid.as_psid(),
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_chars,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_chars,
                &mut usage,
            )
        };
        match result {
            Ok(()) => {
                if name_chars as usize > name.len() || domain_chars as usize > domain.len() {
                    bail!("LookupAccountSidW returned invalid string lengths");
                }
                return Ok(AccountName {
                    name: String::from_utf16_lossy(&name[..name_chars as usize]),
                    domain: String::from_utf16_lossy(&domain[..domain_chars as usize]),
                    usage,
                });
            }
            Err(error) if error.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                name.resize(checked_lookup_size(name_chars)?, 0);
                domain.resize(checked_lookup_size(domain_chars)?, 0);
            }
            Err(error) => return Err(error).context("LookupAccountSidW"),
        }
    }
    bail!("LookupAccountSidW did not converge after {LOOKUP_ATTEMPTS} attempts")
}

fn local_group_sid(name: &str, sam: &LocalSam) -> Result<Sid> {
    let account = match lookup_name(&format!("{}\\{name}", sam.name)) {
        Ok(account) => account,
        Err(error) if has_win32_code(&error, ERROR_NONE_MAPPED.0) => {
            lookup_name(&format!("BUILTIN\\{name}"))?
        }
        Err(error) => return Err(error),
    };
    if account.1 != SidTypeAlias || !is_local_sid(&account.0.text()?, sam) {
        bail!("Local group lookup resolved outside the local account or BUILTIN domain");
    }
    Ok(account.0)
}

struct Group {
    name: String,
    description: String,
}

fn enumerate_groups(budget: &mut EnumerationBudget) -> Result<Vec<Group>> {
    let mut groups = Vec::new();
    let mut resume = 0usize;
    loop {
        budget.start_page("NetLocalGroupEnum")?;
        let previous_resume = resume;
        let mut buffer = NetBuffer::default();
        let mut count = 0;
        let mut total = 0;
        let status = unsafe {
            NetLocalGroupEnum(
                None,
                1,
                &mut buffer.0,
                PAGE_BYTES,
                &mut count,
                &mut total,
                Some(&mut resume),
            )
        };
        let more = budget.finish_page(
            "NetLocalGroupEnum",
            status,
            count,
            resume != previous_resume,
        )?;
        unsafe {
            for info in buffer.entries::<LOCALGROUP_INFO_1>(count)? {
                groups.push(Group {
                    name: from_wide(info.lgrpi1_name.0),
                    description: from_wide(info.lgrpi1_comment.0),
                });
            }
        }
        if !more {
            return Ok(groups);
        }
    }
}

fn member_sids(group: &str, budget: &mut EnumerationBudget) -> Result<Vec<Sid>> {
    validate_local_name(group, "Group name", GNLEN as usize)?;
    let group = to_wide(group);
    let mut members = Vec::new();
    let mut resume = 0usize;
    loop {
        budget.start_page("NetLocalGroupGetMembers")?;
        let previous_resume = resume;
        let mut buffer = NetBuffer::default();
        let mut count = 0;
        let mut total = 0;
        // Level 0 also works when a group contains a deleted or offline-domain principal.
        let status = unsafe {
            NetLocalGroupGetMembers(
                None,
                PCWSTR(group.as_ptr()),
                0,
                &mut buffer.0,
                PAGE_BYTES,
                &mut count,
                &mut total,
                Some(&mut resume),
            )
        };
        let more = budget.finish_page(
            "NetLocalGroupGetMembers",
            status,
            count,
            resume != previous_resume,
        )?;
        unsafe {
            for info in buffer.entries::<LOCALGROUP_MEMBERS_INFO_0>(count)? {
                members.push(Sid::copy(info.lgrmi0_sid)?);
            }
        }
        if !more {
            return Ok(members);
        }
    }
}

fn sort_names(values: &mut [Value]) {
    values.sort_by(|left, right| left["Name"].as_str().cmp(&right["Name"].as_str()));
}

fn list_groups() -> Result<String> {
    let sam = LocalSam::read()?;
    let mut budget = EnumerationBudget::default();
    let mut groups = Vec::new();
    for group in enumerate_groups(&mut budget)? {
        let sid = local_group_sid(&group.name, &sam).with_context(|| {
            format!(
                "Partial group list: SID for '{}' is unavailable",
                group.name
            )
        })?;
        groups.push(json!({
            "Name": group.name,
            "Description": group.description,
            "SID": sid.text()?,
        }));
    }
    sort_names(&mut groups);
    Ok(pretty(&json!(groups)))
}

fn local_user_source(name: &str, sid: &Sid) -> Result<&'static str> {
    let wide = to_wide(name);
    let mut buffer = NetBuffer::default();
    unsafe {
        net_result(
            NetUserGetInfo(None, PCWSTR(wide.as_ptr()), 24, &mut buffer.0),
            "NetUserGetInfo(level 24, local identity provider)",
        )?;
        let info = &buffer.entries::<USER_INFO_24>(1)?[0];
        if !info.usri24_internet_identity.as_bool() {
            // The other level-24 fields are undefined for an unconnected account.
            let current = read_user(name)?;
            if !current
                .sid
                .as_ref()
                .is_some_and(|current| current.equals(sid))
            {
                bail!("The local account SID changed during identity-provider lookup");
            }
            return Ok("Local");
        }
        if !Sid::copy(info.usri24_user_sid)?.equals(sid) {
            bail!("The local account SID changed during identity-provider lookup");
        }
        let provider = from_wide(info.usri24_internet_provider_name.0);
        if provider.eq_ignore_ascii_case("MicrosoftAccount") {
            Ok("MicrosoftAccount")
        } else if provider.eq_ignore_ascii_case("AzureAD") {
            Ok("AzureAD")
        } else {
            bail!("Windows reported an unrecognized internet identity provider");
        }
    }
}

fn principal_source(
    sid: &Sid,
    text: &str,
    name: &AccountName,
    sam: &LocalSam,
) -> Result<&'static str> {
    if belongs_to_domain(text, &sam.sid) {
        if name.usage == SidTypeUser {
            return local_user_source(&name.name, sid);
        }
        return Ok("Local");
    }
    if belongs_to_domain(text, "S-1-5-32") || name.usage == SidTypeWellKnownGroup {
        return Ok("Local");
    }
    if name.domain.eq_ignore_ascii_case("AzureAD") {
        return Ok("AzureAD");
    }
    if name.domain.eq_ignore_ascii_case("MicrosoftAccount") {
        return Ok("MicrosoftAccount");
    }
    if text.starts_with("S-1-5-21-") && !name.domain.is_empty() {
        // A nonlocal account-domain SID was successfully resolved by the local LSA.
        return Ok("ActiveDirectory");
    }
    bail!("Windows name resolution did not identify a local, directory, or internet account source")
}

fn object_class(usage: SID_NAME_USE) -> &'static str {
    if usage == SidTypeUser {
        "User"
    } else if usage == SidTypeGroup || usage == SidTypeAlias || usage == SidTypeWellKnownGroup {
        "Group"
    } else if usage == SidTypeComputer {
        "Computer"
    } else if usage == SidTypeDomain {
        "Domain"
    } else {
        "Unavailable"
    }
}

fn list_group_members(name: &str) -> Result<String> {
    validate_local_name(name, "Group name", GNLEN as usize)?;
    let sam = LocalSam::read()?;
    let mut budget = EnumerationBudget::default();
    let mut members = Vec::new();
    for sid in member_sids(name, &mut budget)? {
        let text = sid.text()?;
        let value = match lookup_sid(&sid) {
            Ok(account) => {
                let mut value = json!({
                    "Name": account.qualified(),
                    "ObjectClass": object_class(account.usage),
                    "PrincipalSource": "Unavailable",
                    "SID": text,
                });
                if object_class(account.usage) == "Unavailable" {
                    value["ObjectClassUnavailable"] =
                        json!(format!("Windows returned SID_NAME_USE {}", account.usage.0));
                }
                match principal_source(&sid, &text, &account, &sam) {
                    Ok(source) => value["PrincipalSource"] = json!(source),
                    Err(error) => value["PrincipalSourceUnavailable"] = json!(format!("{error:#}")),
                }
                value
            }
            Err(error) => json!({
                "Name": text,
                "ObjectClass": "Unavailable",
                "PrincipalSource": "Unavailable",
                "SID": text,
                "NameUnavailable": format!("{error:#}"),
                "ObjectClassUnavailable": "The SID could not be resolved to an account",
                "PrincipalSourceUnavailable": "The SID could not be resolved to an account",
            }),
        };
        members.push(value);
    }
    sort_names(&mut members);
    Ok(pretty(&json!(members)))
}

fn resolve_member(member: &str, sam: &LocalSam) -> Result<Sid> {
    validate_member(member)?;
    if member
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("S-1-"))
    {
        return Sid::from_text(member);
    }
    if let Some((domain, name)) = member.split_once('\\') {
        let local = domain == "." || domain.eq_ignore_ascii_case(&sam.name);
        let qualified = if local {
            format!("{}\\{name}", sam.name)
        } else {
            member.to_owned()
        };
        let (sid, _) = lookup_name(&qualified)?;
        if local && !is_local_sid(&sid.text()?, sam) {
            bail!("The member name did not resolve to a local SID");
        }
        return Ok(sid);
    }
    if member.contains('@') {
        return Ok(lookup_name(member)?.0);
    }
    match lookup_name(&format!("{}\\{member}", sam.name)) {
        Ok((sid, _)) => {
            if !is_local_sid(&sid.text()?, sam) {
                bail!("The unqualified member name did not resolve to a local SID");
            }
            return Ok(sid);
        }
        Err(error) if has_win32_code(&error, ERROR_NONE_MAPPED.0) => {}
        Err(error) => return Err(error),
    }
    let (sid, usage) = lookup_name(member)?;
    if is_local_sid(&sid.text()?, sam) || usage == SidTypeWellKnownGroup {
        Ok(sid)
    } else {
        bail!("Use DOMAIN\\name or a UPN for a nonlocal member; unqualified names are local-only")
    }
}

fn change_membership(group: &str, member: &str, add: bool) -> Result<String> {
    validate_local_name(group, "Group name", GNLEN as usize)?;
    validate_member(member)?;
    let sam = LocalSam::read()?;
    let sid = resolve_member(member, &sam)?;
    let group_wide = to_wide(group);
    let info = LOCALGROUP_MEMBERS_INFO_0 {
        lgrmi0_sid: sid.as_psid(),
    };
    let status = unsafe {
        if add {
            NetLocalGroupAddMembers(
                None,
                PCWSTR(group_wide.as_ptr()),
                0,
                (&info as *const LOCALGROUP_MEMBERS_INFO_0).cast(),
                1,
            )
        } else {
            NetLocalGroupDelMembers(
                None,
                PCWSTR(group_wide.as_ptr()),
                0,
                (&info as *const LOCALGROUP_MEMBERS_INFO_0).cast(),
                1,
            )
        }
    };
    net_result(
        status,
        if add {
            "NetLocalGroupAddMembers(level 0, local)"
        } else {
            "NetLocalGroupDelMembers(level 0, local)"
        },
    )?;
    let result = if add {
        json!({ "Group": group, "Added": member, "Status": "Success" })
    } else {
        json!({ "Group": group, "Removed": member, "Status": "Success" })
    };
    Ok(pretty(&result))
}

fn tool_result(result: Result<String>) -> Result<String> {
    // The tool boundary uses Display rather than the alternate error-chain formatter.
    result.map_err(|error| {
        let message = format!("{error:#}");
        error.context(message)
    })
}

pub fn user_list() -> Result<String> {
    tool_result(list_users())
}

pub fn user_detail(name: &str) -> Result<String> {
    tool_result(detail_user(name))
}

pub fn user_create(input: &crate::server::UserCreateInput) -> Result<String> {
    tool_result(create_user(input))
}

pub fn user_delete(name: &str) -> Result<String> {
    tool_result(delete_user(name))
}

pub fn user_modify(input: &crate::server::UserModifyInput) -> Result<String> {
    tool_result(modify_user(input))
}

pub fn group_list() -> Result<String> {
    tool_result(list_groups())
}

pub fn group_members(name: &str) -> Result<String> {
    tool_result(list_group_members(name))
}

pub fn group_add_member(group: &str, member: &str) -> Result<String> {
    tool_result(change_membership(group, member, true))
}

pub fn group_remove_member(group: &str, member: &str) -> Result<String> {
    tool_result(change_membership(group, member, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_names_reject_remote_paths_nuls_and_invalid_characters() {
        for name in [
            "",
            " ",
            ".",
            "name.",
            "DOMAIN\\user",
            "\\\\server\\user",
            "user/name",
            "a\0b",
            "a*",
        ] {
            assert!(validate_local_name(name, "User name", UNLEN as usize).is_err());
        }
        for name in ["Administrator", "O'Brien", "Test User", "\u{540d}\u{524d}"] {
            assert!(validate_local_name(name, "User name", UNLEN as usize).is_ok());
        }
        assert!(validate_local_name(&"a".repeat(21), "User name", CREATE_NAME_CHARS).is_err());
        assert!(validate_text("", "Full name", UNLEN as usize).is_ok());
        assert!(validate_text("a\0b", "Description", MAXCOMMENTSZ as usize).is_err());
        assert!(validate_text(&"a".repeat(257), "Description", MAXCOMMENTSZ as usize).is_err());
    }

    #[test]
    fn member_validation_accepts_qualified_names_but_not_remote_paths() {
        for member in [
            "user",
            ".\\user",
            "DOMAIN\\user",
            "user@example.test",
            "S-1-5-32-544",
        ] {
            assert!(validate_member(member).is_ok());
        }
        for member in ["", " ", "\\\\server\\user", "\\user", "domain\\", "a\0b"] {
            assert!(validate_member(member).is_err());
        }
    }

    #[test]
    fn validation_counts_utf16_units_and_does_not_echo_passwords() {
        assert!(validate_text("\u{10400}", "Full name", 1).is_err());
        assert!(validate_text("\u{10400}", "Full name", 2).is_ok());
        let password = "private-test-value\0must-not-be-echoed";
        let error = PasswordBuffer::new(password)
            .err()
            .expect("NUL must be rejected");
        let message = format!("{error:#}");
        assert!(!message.contains("private-test-value"));
        assert!(!message.contains("must-not-be-echoed"));
        assert!(PasswordBuffer::new(&"x".repeat(PWLEN as usize + 1)).is_err());
    }

    #[test]
    fn password_buffer_preserves_input_then_zeroes_every_unit() {
        let password = "Test-only'`$\\\"value";
        let mut buffer = PasswordBuffer::new(password).unwrap();
        assert_eq!(buffer.0, to_wide(password));
        buffer.clear();
        assert!(buffer.0.iter().all(|unit| *unit == 0));
    }

    #[test]
    fn enabled_changes_preserve_every_unrelated_flag() {
        for flags in [
            0,
            UF_ACCOUNTDISABLE.0,
            UF_NORMAL_ACCOUNT | UF_SCRIPT.0 | UF_DONT_EXPIRE_PASSWD.0 | UF_PASSWD_NOTREQD.0,
            u32::MAX,
            0x8000_0000,
        ] {
            assert_eq!(flags_with_enabled(flags, None), flags);
            let enabled = flags_with_enabled(flags, Some(true));
            let disabled = flags_with_enabled(flags, Some(false));
            assert_eq!(enabled & UF_ACCOUNTDISABLE.0, 0);
            assert_ne!(disabled & UF_ACCOUNTDISABLE.0, 0);
            assert_eq!(enabled & !UF_ACCOUNTDISABLE.0, flags & !UF_ACCOUNTDISABLE.0);
            assert_eq!(
                disabled & !UF_ACCOUNTDISABLE.0,
                flags & !UF_ACCOUNTDISABLE.0
            );
        }
    }

    #[test]
    fn sid_domain_matching_requires_the_exact_domain_and_one_rid() {
        let domain = "S-1-5-21-1-2-3";
        assert!(belongs_to_domain("S-1-5-21-1-2-3-1001", domain));
        for sid in [
            "S-1-5-21-1-2-30-1001",
            "S-1-5-21-1-2-3",
            "S-1-5-21-1-2-3-1001-9",
            "S-1-5-21-1-2-3-",
        ] {
            assert!(!belongs_to_domain(sid, domain));
        }
    }

    #[test]
    fn enumeration_limits_and_stalled_pages_are_explicit_errors() {
        let mut budget = EnumerationBudget::default();
        budget.start_page("test").unwrap();
        assert!(budget
            .finish_page("test", ERROR_MORE_DATA.0, 1, true)
            .unwrap());
        assert!(!budget.finish_page("test", NERR_Success, 0, false).unwrap());
        assert!(budget
            .finish_page("test", ERROR_MORE_DATA.0, 0, true)
            .is_err());
        assert!(budget
            .finish_page("test", ERROR_MORE_DATA.0, 1, false)
            .is_err());
        budget.entries = MAX_ENUM_ENTRIES;
        assert!(budget.finish_page("test", NERR_Success, 1, false).is_err());
        budget.pages = MAX_ENUM_PAGES;
        let error = budget.start_page("test").unwrap_err();
        assert!(error.to_string().contains("Partial"));
    }

    #[test]
    fn tool_errors_preserve_native_context_and_error_codes() {
        let result = net_result(5, "test NetAPI")
            .context("A prior field was applied")
            .map(|()| String::new());
        let error = tool_result(result).unwrap_err();
        assert!(error.to_string().contains("A prior field was applied"));
        assert!(error.to_string().contains("test NetAPI"));
        assert!(error.to_string().contains("Win32 5"));
        assert!(has_win32_code(&error, 5));
    }

    fn read_only_available<T>(operation: &str, result: Result<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                // These failures describe host availability or access, not account data.
                let unavailable = [5, 50, 120, 1062, 1311, 1314, 1355, 1722, 2114]
                    .iter()
                    .any(|code| has_win32_code(&error, *code));
                if unavailable {
                    eprintln!("{operation} unavailable on this host: {error:#}");
                    None
                } else {
                    panic!("{operation} failed: {error:#}");
                }
            }
        }
    }

    #[test]
    fn read_only_local_user_list_and_detail() {
        let Some(list) = read_only_available("user_list", user_list()) else {
            return;
        };
        let users: Value = serde_json::from_str(&list).unwrap();
        let users = users
            .as_array()
            .expect("user_list must always return an array");
        for user in users {
            for field in [
                "Name",
                "FullName",
                "Enabled",
                "LastLogon",
                "PasswordRequired",
                "PasswordLastSet",
                "Description",
            ] {
                assert!(user.get(field).is_some(), "Missing {field}");
            }
            assert!(user["Enabled"].is_boolean());
            assert!(user["PasswordRequired"].is_boolean());
        }
        let Some(name) = users.first().and_then(|user| user["Name"].as_str()) else {
            eprintln!("user_detail unavailable: no local users were returned");
            return;
        };
        let Some(detail) = read_only_available("user_detail", user_detail(name)) else {
            return;
        };
        let detail: Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(detail["Name"], name);
        assert!(detail["SID"].as_str().unwrap().starts_with("S-1-"));
        assert!(detail["Groups"].is_array());
        assert!(detail.get("PasswordExpires").is_some());
    }

    #[test]
    fn read_only_local_groups_and_members() {
        let Some(list) = read_only_available("group_list", group_list()) else {
            return;
        };
        let groups: Value = serde_json::from_str(&list).unwrap();
        let groups = groups
            .as_array()
            .expect("group_list must always return an array");
        if groups.is_empty() {
            eprintln!("group_members unavailable: no local groups were returned");
        }
        for group in groups {
            assert!(group["Name"].is_string());
            assert!(group["Description"].is_string());
            assert!(group["SID"].as_str().unwrap().starts_with("S-1-"));
        }
        for group in groups.iter().take(5) {
            let name = group["Name"].as_str().unwrap();
            let Some(members) = read_only_available("group_members", group_members(name)) else {
                return;
            };
            let members: Value = serde_json::from_str(&members).unwrap();
            for member in members
                .as_array()
                .expect("group_members must always return an array")
            {
                assert!(member["Name"].is_string());
                assert!(!member["Name"].as_str().unwrap().contains('\0'));
                assert!(member["ObjectClass"].is_string());
                assert!(member["PrincipalSource"].is_string());
                if member["PrincipalSource"] == "Unavailable" {
                    assert!(member["PrincipalSourceUnavailable"].is_string());
                }
                if member["ObjectClass"] == "Unavailable" {
                    assert!(member["ObjectClassUnavailable"].is_string());
                }
            }
        }
    }
}

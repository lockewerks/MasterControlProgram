//! PowerShell subsystem — because Windows couldn't just give us nice C APIs
//! for *everything*, so 57 of our 90 tools still have to talk to pwsh.exe
//! like it's 2015 and we're writing deployment scripts.

mod pool;
pub use pool::Pool;

/// This module contains struct FileRecord. FileRecord correspondes to an NTFS File Record with all attributes.
mod file_record;

/// This module enumerates all files on a volume via DeviceIoControl() win32 calls.
pub mod mft;

mod usn_record;
/// This module wraps unsafe function calls to winapi-rs. This is the only module
/// with unsafe code.
pub mod winapi_ffi;

/// Converts a &str to a wide OsStr (utf16)
fn str_to_wstring(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// todo add function to convert &u8 to vec<u16> to get UTF_16LE strings

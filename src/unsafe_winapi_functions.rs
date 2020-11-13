//
// see https://stackoverflow.com/questions/21661798/how-do-we-access-mft-through-c-sharp/45646777#45646777
// for an outline of what was implemented here.
//

extern crate winapi;

use std::mem;
use std::ptr;
use winapi::_core::i64;
use winapi::shared::minwindef::{DWORD, LPDWORD, LPVOID, MAX_PATH, WORD};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::fileapi::{CreateFileW, GetVolumeNameForVolumeMountPointW};
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::winbase::LookupPrivilegeValueW;
use winapi::um::winioctl::FSCTL_ENUM_USN_DATA;
use winapi::um::winnt::{DWORDLONG, HANDLE, LARGE_INTEGER, TOKEN_PRIVILEGES, USN, WCHAR};
use winapi::um::winnt::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES,
};

/// Needed by DeviceIoControl() when reading the MFT
///
/// [MFT_ENUM_DATA_V0](https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-mft_enum_data_v0)
#[repr(C)]
struct MFT_ENUM_DATA_V0 {
    StartFileReferenceNumber: DWORDLONG,
    LowUsn: USN,
    HighUsn: USN,
}

// https://github.com/netaneld122/ddup/blob/6aa8fe63fba1835e29d3e6e38f40d265a133184b/src/winioctl.rs#L35
#[repr(C)]
pub struct USN_RECORD {
    pub RecordLength: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub FileReferenceNumber: DWORDLONG,
    pub ParentFileReferenceNumber: DWORDLONG,
    pub Usn: USN,
    pub TimeStamp: LARGE_INTEGER,
    pub Reason: DWORD,
    pub SourceInfo: DWORD,
    pub SecurityId: DWORD,
    pub FileAttributes: DWORD,
    pub FileNameLength: WORD,
    pub FileNameOffset: WORD,
    pub FileName: [WCHAR; 1],
}
/// Converts a &str to a wide OsStr (utf16)
fn to_wstring(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// walk the master file table (MFT)
pub fn read_mft(volume_handle: HANDLE) {
    let mut output_buffer = [0u8; 1024 * 128]; // data out from DeviceIoControl()
    let mut input_buffer = MFT_ENUM_DATA_V0 {
        // into DeviceIoControl()
        StartFileReferenceNumber: 0,
        LowUsn: 0,
        HighUsn: i64::MAX,
    };

    for looped in 0..=500 {
        let mut buffer_cursor: usize = 8;
        let mut bytes_read: u32 = 0;

        unsafe {
            // https://github.com/forensicmatt/RsWindowsThingies/blob/e9bbb44130fb54eb38c39f88082f33b5c86b9196/src/usn/winioctrl.rs#L75
            if DeviceIoControl(
                volume_handle,
                FSCTL_ENUM_USN_DATA,
                //&mut input_buffer.StartFileReferenceNumber as *mut _ as *mut c_void, // what does this mean?
                &input_buffer as *const MFT_ENUM_DATA_V0 as LPVOID, // what does this mean?
                mem::size_of::<MFT_ENUM_DATA_V0>() as DWORD,
                output_buffer.as_mut_ptr() as *mut USN_RECORD as LPVOID,
                output_buffer.len() as DWORD,
                &mut bytes_read as LPDWORD,
                ptr::null_mut(),
            ) == 0
            {
                match GetLastError() {
                    38 => {
                        // Error 38 is EOF
                        println!("Reached EOF $MFT");
                        std::process::exit(0);
                    }
                    _ => {
                        println!("DeviceIoControl failed. Error {}", GetLastError());
                        std::process::exit(GetLastError() as i32);
                    }
                }
            }
        }

        println!("bytes_read {}", bytes_read);
        println!(
            "current StartFileReferenceNumber = {}",
            input_buffer.StartFileReferenceNumber
        );
        input_buffer.StartFileReferenceNumber = unsafe { *(output_buffer.as_ptr() as *const u64) };
        println!(
            "next StartFileReferenceNumber = {}",
            input_buffer.StartFileReferenceNumber
        );

        // todo: understand why it's <= instead of <
        while buffer_cursor < bytes_read as usize {
            println!("\n\n===================");
            println!("bytes_read {}", bytes_read);
            println!("loop #: {}", looped);
            println!("buffer_cursor = {}", buffer_cursor);

            // record_length 4 bytes, [0..4]
            println!("DWORD length = {}", std::mem::size_of::<DWORD>());
            let mut record_length = [0u8; 4];
            record_length.clone_from_slice(&output_buffer[buffer_cursor + 0..buffer_cursor + 4]);
            println!(
                "record_length = {}, {} bytes, {:?}",
                u32::from_le_bytes(record_length),
                record_length.len(),
                record_length
            );

            // 2 bytes
            let mut major_version = [0u8; 2];
            major_version.clone_from_slice(&output_buffer[buffer_cursor + 4..buffer_cursor + 6]);
            println!(
                "major_version {}, {} bytes, {:?}",
                u16::from_le_bytes(major_version),
                major_version.len(),
                major_version
            );
            let mut minor_version = [0u8; 2];
            minor_version.clone_from_slice(&output_buffer[buffer_cursor + 6..buffer_cursor + 8]);
            println!(
                "minor_version {}, {} bytes, {:?}",
                u16::from_le_bytes(minor_version),
                minor_version.len(),
                minor_version
            );
            let mut file_reference_number = [0u8; 8];
            file_reference_number
                .clone_from_slice(&output_buffer[buffer_cursor + 8..buffer_cursor + 16]);
            println!(
                "file_reference_number {}, {} bytes, {:?}",
                u64::from_le_bytes(file_reference_number),
                file_reference_number.len(),
                file_reference_number
            );
            let mut parent_file_reference_number = [0u8; 8];
            parent_file_reference_number
                .clone_from_slice(&output_buffer[buffer_cursor + 16..buffer_cursor + 24]);
            println!(
                "parent_file_reference_number {}, {} bytes, {:?}",
                u64::from_le_bytes(parent_file_reference_number),
                parent_file_reference_number.len(),
                parent_file_reference_number
            );
            let mut usn = [0u8; 8];
            usn.clone_from_slice(&output_buffer[buffer_cursor + 24..buffer_cursor + 32]);
            println!(
                "usn {}, {} bytes, {:?}",
                i64::from_le_bytes(usn),
                usn.len(),
                usn
            );
            // need to figure out how to convert this into a readable time
            // might help: https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
            let mut timestamp = [0u8; 8];
            timestamp.clone_from_slice(&output_buffer[buffer_cursor + 32..buffer_cursor + 40]);
            println!(
                "timestamp {}, {} bytes, {:?}",
                i64::from_le_bytes(timestamp),
                timestamp.len(),
                timestamp
            );

            let mut reason = [0u8; 4];
            reason.clone_from_slice(&output_buffer[buffer_cursor + 40..buffer_cursor + 44]);
            println!(
                "reason {:#x}, {} bytes, {:?}",
                u32::from_le_bytes(reason),
                reason.len(),
                reason
            );

            // source_info 4 bytes, [44..48]
            let mut source_info = [0u8; 4];
            source_info.clone_from_slice(&output_buffer[buffer_cursor + 44..buffer_cursor + 48]);
            println!(
                "source_info {:#x}, {} bytes, {:?}",
                u32::from_le_bytes(source_info),
                source_info.len(),
                source_info
            );

            // security_id 4 bytes, [48..52]
            let mut security_id = [0u8; 4];
            security_id.clone_from_slice(&output_buffer[buffer_cursor + 48..buffer_cursor + 52]);
            println!(
                "security_id {:#x}, {} bytes, {:?}",
                u32::from_le_bytes(security_id),
                security_id.len(),
                security_id
            );

            // file_attributes 4 bytes, [52..56]
            let mut file_attributes = [0u8; 4];
            file_attributes
                .clone_from_slice(&output_buffer[buffer_cursor + 52..buffer_cursor + 56]);
            println!(
                "file_attributes {}, {} bytes, {:?}",
                u32::from_le_bytes(file_attributes),
                file_attributes.len(),
                file_attributes
            );
            // file_name_length 2 bytes [56..58]
            let mut file_name_length = [0u8; 2];
            file_name_length
                .clone_from_slice(&output_buffer[buffer_cursor + 56..buffer_cursor + 58]);
            let file_name_length_u16 = u16::from_le_bytes(file_name_length);
            println!(
                "file_name_length {}, {} bytes, {:?}",
                u16::from_le_bytes(file_name_length),
                file_name_length.len(),
                file_name_length
            );
            let file_name_length = u16::from_le_bytes(file_name_length);

            // file_name_offset 2 bytes [58..60]
            let mut file_name_offset = [0u8; 2];
            file_name_offset
                .clone_from_slice(&output_buffer[buffer_cursor + 58..buffer_cursor + 60]);
            let file_name_offset_u16 = u16::from_le_bytes(file_name_offset);
            println!(
                "file_name_offset {}, {} bytes, {:?}",
                u16::from_le_bytes(file_name_offset),
                file_name_offset.len(),
                file_name_offset
            );
            let file_name_offset = u16::from_le_bytes(file_name_offset);

            if file_name_length > 0 {
                println!("************************");

                let file_name = unsafe {
                    output_buffer
                        .as_ptr()
                        .offset(buffer_cursor as isize + file_name_offset as isize)
                        as *const u16
                };
                let file_name = unsafe {
                    // todo: why is file_name_length / 2 here?
                    std::slice::from_raw_parts(file_name, (file_name_length / 2) as usize)
                };
                let file_name = String::from_utf16_lossy(file_name);
                println!("file_name = {}", file_name);

                println!("************************");
            }

            // move the cursor to the start of the next record
            buffer_cursor = buffer_cursor + (u32::from_le_bytes(record_length) as usize);
        }
    }
}

/**

Assert the SE_BACKUP_NAME and SE_RESTORE_NAME privileges required to get a handle to the volume.

References:

- [https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--)

Steps to assert privileges

1. get process token to the current process
1. create TOKEN_PRIVILEGES struct
1. set privileges

*/
pub fn assert_security_privileges() {
    unsafe {
        let mut proc_token: HANDLE = ptr::null_mut();
        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        // https://github.com/ricostrong/mesosfuzz/blob/13c599f89610008f6cbfe953c0761dd472fe67e4/libs/debugger/src/sedebug.rs#L20
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES,
            &mut proc_token,
        ) == 0
        {
            println!("OpenProcessToken error {}", GetLastError());
            println!("See https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes");
        }

        // Set privileges for the process
        let privileges: [&str; 2] = ["SeBackupPrivilege", "SeRestorePrivilege"];
        for i in 0..=1 {
            let mut token_privileges: TOKEN_PRIVILEGES = std::mem::zeroed();

            // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
            if LookupPrivilegeValueW(
                ptr::null(),
                to_wstring(privileges[i]).as_ptr(),
                &mut token_privileges.Privileges[0].Luid,
            ) == 0
            {
                println!("LookupPrivilegeValueW error {}", GetLastError());
                println!(
                    "See https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes"
                );
            }
            token_privileges.PrivilegeCount = 1;
            token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
            if AdjustTokenPrivileges(
                proc_token,
                0,
                &mut token_privileges,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                let e = GetLastError();
                println!("AdjustTokenPrivileges failed, error {}", e);
                println!("Unable to adjust privileges. Be sure to run with elevated permissions.");
                std::process::exit(e as i32);
            }
            if GetLastError() == 1300
            // ERROR_NOT_ALL_ASSIGNED
            {
                println!(
                    "\n*** Unable to adjust privileges. Try running as an administrator. ***\n"
                );
                std::process::exit(1300);
            }
        }
        // close our process token handle
        CloseHandle(proc_token);
    }
}

/** get_volume_guid will get the unique volume name (GUID).

Example return value:

```text
\\?\Volume{6eb8a49a-0000-0000-0000-300300000000}\
```
*/
pub fn get_volume_guid(drive: &str) -> Option<String> {
    unsafe {
        let volume_guid = &mut [0; MAX_PATH + 1];
        if GetVolumeNameForVolumeMountPointW(
            to_wstring(drive).as_ptr(),
            volume_guid.as_mut_ptr(),
            volume_guid.len() as u32,
        ) == 1
        {
            Some(String::from_utf16_lossy(
                &volume_guid[..volume_guid
                    .iter()
                    .position(|v| *v == 0)
                    .unwrap_or(volume_guid.len())],
            ))
        } else {
            None
        }
    }
}

/**
Gets a handle to a volume using the volume GUID. Must be run with administrator privileges.

_NOTE:_ the volume guid should __not__ have a trailing slash `\`. The trailing backslash
points to the root directory of the volume instead of the volume itself.

Example volume GUID: `\\?\Volume{6eb8a49a-0000-0000-0000-300300000000}`

*/
pub fn get_file_read_handle(volume: &str) -> Option<HANDLE> {
    unsafe {
        let handle = CreateFileW(
            to_wstring(volume).as_ptr(),
            GENERIC_READ,
            // opening with FILE_SHARE_READ only gives a ERROR_SHARING_VIOLATION error
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );

        if handle == INVALID_HANDLE_VALUE {
            let x = winapi::um::errhandlingapi::GetLastError();
            println!("invalid handle value: {:#?}, error == {:#?}", handle, x);
            println!("See https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes");
        }
        Some(handle)
    }
}

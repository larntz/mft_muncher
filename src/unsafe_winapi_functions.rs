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
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
struct MFT_ENUM_DATA_V0 {
    StartFileReferenceNumber: DWORDLONG,
    LowUsn: USN,
    HighUsn: USN,
}

// https://github.com/netaneld122/ddup/blob/6aa8fe63fba1835e29d3e6e38f40d265a133184b/src/winioctl.rs#L35
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
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

    let mut mft_eof: bool = false;
    while !mft_eof {
        let mut buffer_cursor: isize = 8;
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
                        println!("Reached mft_eof");
                        mft_eof = true;
                        continue;
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

        while buffer_cursor < bytes_read as isize {
            // println!("\n\n===================");
            // println!("bytes_read {}", bytes_read);
            // println!("buffer_cursor = {}", buffer_cursor);

            let buffer_pointer = output_buffer.as_ptr();
            let buffer_pointer = unsafe { buffer_pointer.offset(buffer_cursor) };
            let usn_record: &USN_RECORD = unsafe { std::mem::transmute(buffer_pointer) };

            // println!("record length == {}", usn_record.RecordLength);
            // println!(
            //     "usn record version == {}.{}",
            //     usn_record.MajorVersion, usn_record.MinorVersion
            // );
            // println!("FileReferenceNumber == {}", usn_record.FileReferenceNumber);
            // println!(
            //     "ParentFileReferenceNumber == {}",
            //     usn_record.ParentFileReferenceNumber
            // );
            // println!("Usn == {}", usn_record.Usn);
            // // can't be formatted
            // //println!("TimeStamp == {:#?}", usn_record.TimeStamp);
            // println!("Reason == {:x}", usn_record.Reason);
            // println!("SourceInfo == {:x}", usn_record.SourceInfo);
            // println!("SecurityID == {:x}", usn_record.SecurityId);
            // println!("FileAttributes == {}", usn_record.FileAttributes);
            // println!("FileNameLength == {}", usn_record.FileNameLength);
            // println!("FileNameOffset == {}", usn_record.FileNameOffset);

            // let file_name = unsafe {
            //     output_buffer
            //         .as_ptr()
            //         .offset(buffer_cursor as isize + usn_record.FileNameOffset as isize)
            //         as *const u16
            // };
            // let file_name = unsafe {
            //     // todo: why is file_name_length / 2 here?
            //     std::slice::from_raw_parts(file_name, (usn_record.FileNameLength / 2) as usize)
            // };
            // let file_name = String::from_utf16_lossy(file_name);
            // println!("file_name = {}", file_name);

            // move the cursor to the start of the next record
            buffer_cursor = buffer_cursor + (usn_record.RecordLength as isize);
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

//
// see https://stackoverflow.com/questions/21661798/how-do-we-access-mft-through-c-sharp/45646777#45646777
// for an outline of what was implemented here.
//

extern crate winapi;

use std::mem;
use std::ptr;
use winapi::_core::i64;
use winapi::shared::minwindef::MAX_PATH;
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
use winapi::um::winnt::{DWORDLONG, HANDLE, TOKEN_PRIVILEGES, USN};
use winapi::um::winnt::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES,
};

/// Needed by DeviceIoControl() when reading the MFT
///
/// [MFT_ENUM_DATA_V0](https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-mft_enum_data_v0)
#[allow(non_snake_case)]
#[repr(C)]
struct MFT_ENUM_DATA_V0 {
    StartFileReferenceNumber: DWORDLONG,
    LowUsn: USN,
    HighUsn: USN,
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
    let mut output_buffer = [0u8; 1024 * 1024]; // data out from DeviceIoControl()
    let mut input_buffer = MFT_ENUM_DATA_V0 {
        // into DeviceIoControl()
        StartFileReferenceNumber: 0,
        LowUsn: 0,
        HighUsn: i64::MAX,
    };

    unsafe {
        use winapi::ctypes::c_void;
        let mut bytes_read = 0;
        // https://github.com/forensicmatt/RsWindowsThingies/blob/e9bbb44130fb54eb38c39f88082f33b5c86b9196/src/usn/winioctrl.rs#L75
        if DeviceIoControl(
            volume_handle,
            FSCTL_ENUM_USN_DATA,
            &mut input_buffer.StartFileReferenceNumber as *mut _ as *mut c_void, // what does this do?
            mem::size_of::<MFT_ENUM_DATA_V0>() as u32,
            output_buffer.as_mut_ptr() as *mut c_void,
            output_buffer.len() as u32,
            bytes_read as *mut u32,
            ptr::null_mut(),
        ) == 0
        {
            println!("DeviceIoControl failed. Error {}", GetLastError());
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
pub fn get_file_read_handle(volume: &str) {
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
    }
}

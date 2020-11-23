//
// see https://stackoverflow.com/questions/21661798/how-do-we-access-mft-through-c-sharp/45646777#45646777
// for an outline of what was implemented here.
//

extern crate winapi;

use chrono::prelude::*;
use std::mem;
use std::ptr;
use winapi::_core::i64;
use winapi::shared::minwindef::{DWORD, LPDWORD, LPVOID, MAX_PATH, WORD};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::fileapi::{
    CreateFileW, GetVolumeNameForVolumeMountPointW, BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO,
    FILE_STANDARD_INFO,
};
use winapi::um::fileapi::{GetFileInformationByHandle, GetFileSizeEx};
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::minwinbase::SYSTEMTIME;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::timezoneapi::FileTimeToSystemTime;
use winapi::um::winbase::{
    FILE_ID_DESCRIPTOR_u, LookupPrivilegeValueW, OpenFileById, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_ID_DESCRIPTOR, LPFILE_ID_DESCRIPTOR,
};
use winapi::um::winioctl::FSCTL_ENUM_USN_DATA;
use winapi::um::winnt::{DWORDLONG, HANDLE, LARGE_INTEGER, TOKEN_PRIVILEGES, USN, WCHAR};
use winapi::um::winnt::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
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

#[repr(C)]
pub struct FILE_ID_DESCRIPTOR_0 {
    pub dwSize: DWORD,
    pub Type: u32,
    pub FileId: u64,
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

pub enum FileDirectory {
    File,
    Directory,
}

pub struct FileInfo {
    pub file_name: String,
    pub file_reference_number: u64,
    pub parent_reference_number: u64,
    pub usn: u64,
    pub file_attributes: u32,
    pub file_size_bytes: u64,
    pub file_created: DateTime<Utc>,
    pub file_accessed: DateTime<Utc>,
    pub file_written: DateTime<Utc>,
}

/// Converts a &str to a wide OsStr (utf16)
fn to_wstring(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/* TODO
 1. OpenFileById to get a handle on that file!

 2. NtQueryInformationFile to get FILE_BASIC_INFORMATION
      i. this gives us
              typedef struct _FILE_BASIC_INFORMATION {
                  LARGE_INTEGER CreationTime;
                  LARGE_INTEGER LastAccessTime;
                  LARGE_INTEGER LastWriteTime;
                  LARGE_INTEGER ChangeTime;
                  ULONG         FileAttributes;
              } FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;
          https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_basic_information

 3. NtQueryInformationFile to get FILE_STANDARD_INFORMATION
      i. this gives us
              typedef struct _FILE_STANDARD_INFORMATION {
                  LARGE_INTEGER AllocationSize;
                  LARGE_INTEGER EndOfFile;
                  ULONG         NumberOfLinks;
                  BOOLEAN       DeletePending;
                  BOOLEAN       Directory;
              } FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;
          https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_standard_information
*/
pub fn get_file_info_details(
    file_reference_number: u64,
    volume_handle: HANDLE,
    file_info: &mut FileInfo,
) -> &mut FileInfo {
    unsafe {
        let mut u: FILE_ID_DESCRIPTOR_u = std::mem::zeroed::<FILE_ID_DESCRIPTOR_u>();
        let mut l: LARGE_INTEGER = std::mem::zeroed::<LARGE_INTEGER>();
        *l.QuadPart_mut() = file_reference_number as i64;
        *u.FileId_mut() = l;

        let mut fid: FILE_ID_DESCRIPTOR = FILE_ID_DESCRIPTOR {
            dwSize: mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: 0,
            u,
        };
        let fid_ptr: *mut FILE_ID_DESCRIPTOR = &mut fid;
        match OpenFileById(
            volume_handle,
            fid_ptr,
            GENERIC_READ,
            FILE_SHARE_READ, // | FILE_SHARE_WRITE,
            ptr::null_mut(),
            FILE_FLAG_BACKUP_SEMANTICS,
        ) {
            INVALID_HANDLE_VALUE => {
                //println!("INVALID_HANDLE_VALUE from OpenFileById");
            }
            f_handle => {
                let mut file_info_by_handle: BY_HANDLE_FILE_INFORMATION =
                    std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>();
                let file_info_ptr: *mut BY_HANDLE_FILE_INFORMATION = &mut file_info_by_handle;
                GetFileInformationByHandle(f_handle, file_info_ptr);

                // look into this more and understand exactly how this is works
                // see below for a way to verify the math is correct
                file_info.file_size_bytes = ((file_info_by_handle.nFileSizeHigh as u64)
                    << (std::mem::size_of::<DWORD>() * 8))
                    | file_info_by_handle.nFileSizeLow as u64;

                let mut c_system_time: SYSTEMTIME = std::mem::zeroed::<SYSTEMTIME>();
                let mut system_time_ptr: *mut SYSTEMTIME = &mut c_system_time;
                FileTimeToSystemTime(&file_info_by_handle.ftCreationTime, system_time_ptr);
                file_info.file_created = Utc
                    .ymd(
                        c_system_time.wYear as i32,
                        c_system_time.wMonth as u32,
                        c_system_time.wDay as u32,
                    )
                    .and_hms(
                        c_system_time.wHour as u32,
                        c_system_time.wMinute as u32,
                        c_system_time.wSecond as u32,
                    );

                let mut a_system_time: SYSTEMTIME = std::mem::zeroed::<SYSTEMTIME>();
                let mut system_time_ptr: *mut SYSTEMTIME = &mut a_system_time;
                FileTimeToSystemTime(&file_info_by_handle.ftCreationTime, system_time_ptr);
                file_info.file_accessed = Utc
                    .ymd(
                        a_system_time.wYear as i32,
                        a_system_time.wMonth as u32,
                        a_system_time.wDay as u32,
                    )
                    .and_hms(
                        a_system_time.wHour as u32,
                        a_system_time.wMinute as u32,
                        a_system_time.wSecond as u32,
                    );

                let mut w_system_time: SYSTEMTIME = std::mem::zeroed::<SYSTEMTIME>();
                let mut system_time_ptr: *mut SYSTEMTIME = &mut w_system_time;
                FileTimeToSystemTime(&file_info_by_handle.ftCreationTime, system_time_ptr);
                file_info.file_written = Utc
                    .ymd(
                        w_system_time.wYear as i32,
                        w_system_time.wMonth as u32,
                        w_system_time.wDay as u32,
                    )
                    .and_hms(
                        w_system_time.wHour as u32,
                        w_system_time.wMinute as u32,
                        w_system_time.wSecond as u32,
                    );

                CloseHandle(f_handle);
            }
        }
    }
    file_info
}

/// walk the master file table (MFT)
pub fn read_mft(volume_handle: HANDLE) -> Vec<FileInfo> {
    let mut records: Vec<FileInfo> = Vec::with_capacity(524_288); // minimal system has ~300_000 files and dirs
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

        input_buffer.StartFileReferenceNumber = unsafe { *(output_buffer.as_ptr() as *const u64) };

        while buffer_cursor < bytes_read as isize {
            let buffer_pointer = output_buffer.as_ptr();
            let buffer_pointer = unsafe { buffer_pointer.offset(buffer_cursor) };
            let usn_record: &USN_RECORD = unsafe { std::mem::transmute(buffer_pointer) };

            let file_name = unsafe {
                output_buffer
                    .as_ptr()
                    .offset(buffer_cursor as isize + usn_record.FileNameOffset as isize)
                    as *const u16
            };
            let file_name = unsafe {
                // todo: why is file_name_length / 2 here?
                std::slice::from_raw_parts(file_name, (usn_record.FileNameLength / 2) as usize)
            };
            let file_name = String::from_utf16_lossy(file_name);

            records.push(FileInfo {
                file_name,
                file_reference_number: usn_record.FileReferenceNumber as u64,
                parent_reference_number: usn_record.ParentFileReferenceNumber as u64,
                usn: usn_record.Usn as u64,
                file_attributes: usn_record.FileAttributes as u32,
                file_size_bytes: 0,
                file_created: Utc.ymd(1970, 1, 1).and_hms(0, 0, 0),
                file_accessed: Utc.ymd(1970, 1, 1).and_hms(0, 0, 0),
                file_written: Utc.ymd(1970, 1, 1).and_hms(0, 0, 0),
            });

            // move the cursor to the start of the next record
            buffer_cursor = buffer_cursor + (usn_record.RecordLength as isize);
        }
    }
    println!(
        "found {} records (capacity {})",
        records.len(),
        records.capacity()
    );
    println!("size_of FileInfo is {}", std::mem::size_of::<FileInfo>());

    for mut x in records
        .iter_mut()
        .filter(|x| (x.file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        get_file_info_details(x.file_reference_number, volume_handle, &mut x);
    }
    records
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
    let handle = unsafe {
        CreateFileW(
            to_wstring(volume).as_ptr(),
            GENERIC_READ,
            // opening with FILE_SHARE_READ only gives a ERROR_SHARING_VIOLATION error
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let x = unsafe { winapi::um::errhandlingapi::GetLastError() };
        println!("invalid handle value: {:#?}, error == {:#?}", handle, x);
        println!("See https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes");
    }
    Some(handle)
}

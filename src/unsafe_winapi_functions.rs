//
// see https://stackoverflow.com/questions/21661798/how-do-we-access-mft-through-c-sharp/45646777#45646777
// for an outline of what was implemented here.
//

extern crate winapi;

use self::winapi::um::minwinbase::FileNameInfo;
use self::winapi::um::winbase::GetFileInformationByHandleEx;
use chrono::prelude::*;
use std::collections::HashMap;
use std::convert::TryInto;
use std::mem;
use std::ptr;
use std::time::Instant;
use winapi::_core::i64;
use winapi::shared::minwindef::{DWORD, FILETIME, LPDWORD, LPVOID, MAX_PATH, WORD};
use winapi::shared::winerror::ERROR_HANDLE_EOF;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::fileapi::{
    CreateFileW, GetVolumeNameForVolumeMountPointW, BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO,
    FILE_NAME_INFO, FILE_STANDARD_INFO, LPBY_HANDLE_FILE_INFORMATION,
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
use winapi::um::winioctl::{FSCTL_ENUM_USN_DATA, FSCTL_READ_FILE_USN_DATA};
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

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct FILE_ID_DESCRIPTOR_0 {
    pub dwSize: DWORD,
    pub Type: u32,
    pub FileId: u64,
}

// https://github.com/netaneld122/ddup/blob/6aa8fe63fba1835e29d3e6e38f40d265a133184b/src/winioctl.rs#L35
// https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
const USN_RECORD_LENGTH: usize = 320; // size of USN_RECORD in bytes

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct USN_RECORD {
    RecordLength: DWORD,
    MajorVersion: WORD,
    MinorVersion: WORD,
    pub FileReferenceNumber: DWORDLONG,
    pub ParentFileReferenceNumber: DWORDLONG,
    Usn: USN,
    TimeStamp: LARGE_INTEGER,
    Reason: DWORD,
    SourceInfo: DWORD,
    SecurityId: DWORD,
    FileAttributes: DWORD,
    FileNameLength: WORD,
    FileNameOffset: WORD,
    FileName: [u16; 128],
}

impl USN_RECORD {
    pub fn file_name(&self) -> String {
        let filename = unsafe { self.FileName.as_ptr() };
        let filename = unsafe {
            // file_name_length / 2 bc we are using u16 instead of u8 for file name
            std::slice::from_raw_parts(filename, (self.FileNameLength / 2) as usize)
        };
        String::from_utf16_lossy(filename)
    }
    pub fn is_file(&self) -> bool {
        match self.FileAttributes & FILE_ATTRIBUTE_DIRECTORY {
            0 => true,
            _ => false,
        }
    }
    pub fn is_directory(&self) -> bool {
        match self.FileAttributes & FILE_ATTRIBUTE_DIRECTORY {
            0 => false,
            _ => true,
        }
    }
}

// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct FILE_INFORMATION {
    dwFileAttributes: DWORD,
    ftCreationTime: FILETIME,
    ftLastAccessTime: FILETIME,
    ftLastWriteTime: FILETIME,
    dwVolumeSerialNumber: DWORD,
    nFileSizeHigh: DWORD,
    nFileSizeLow: DWORD,
    nNumberOfLinks: DWORD,
    nFileIndexHigh: DWORD,
    nFileIndexLow: DWORD,
}

impl FILE_INFORMATION {
    fn file_size(&self) -> u64 {
        ((self.nFileSizeHigh as u64) << (std::mem::size_of::<DWORD>() * 8))
            | self.nFileSizeLow as u64
    }

    fn creation_time(&self) -> DateTime<Utc> {
        let mut system_time: SYSTEMTIME = unsafe { std::mem::zeroed::<SYSTEMTIME>() };
        let mut system_time_ptr: *mut SYSTEMTIME = &mut system_time;
        unsafe { FileTimeToSystemTime(&self.ftCreationTime, system_time_ptr) };

        Utc.ymd(
            system_time.wYear as i32,
            system_time.wMonth as u32,
            system_time.wDay as u32,
        )
        .and_hms(
            system_time.wHour as u32,
            system_time.wMinute as u32,
            system_time.wSecond as u32,
        )
    }
    fn last_access_time(&self) -> DateTime<Utc> {
        let mut system_time: SYSTEMTIME = unsafe { std::mem::zeroed::<SYSTEMTIME>() };
        let mut system_time_ptr: *mut SYSTEMTIME = &mut system_time;
        unsafe { FileTimeToSystemTime(&self.ftLastAccessTime, system_time_ptr) };

        Utc.ymd(
            system_time.wYear as i32,
            system_time.wMonth as u32,
            system_time.wDay as u32,
        )
        .and_hms(
            system_time.wHour as u32,
            system_time.wMinute as u32,
            system_time.wSecond as u32,
        )
    }
    fn last_write_time(&self) -> DateTime<Utc> {
        let mut system_time: SYSTEMTIME = unsafe { std::mem::zeroed::<SYSTEMTIME>() };
        let mut system_time_ptr: *mut SYSTEMTIME = &mut system_time;
        unsafe { FileTimeToSystemTime(&self.ftLastWriteTime, system_time_ptr) };

        Utc.ymd(
            system_time.wYear as i32,
            system_time.wMonth as u32,
            system_time.wDay as u32,
        )
        .and_hms(
            system_time.wHour as u32,
            system_time.wMinute as u32,
            system_time.wSecond as u32,
        )
    }
}

// not using
// #[derive(Debug)]
// struct DirInfo {
//     size_bytes: u64,
//     children: Vec<u64>,
// }

// not using
// #[derive(Debug)]
// pub struct FileInfo {
//     pub name: String,
//     pub reference_number: u64,
//     pub parent_reference_number: u64,
//     pub attributes: u32,
//     pub size_bytes: u64,
//     pub created: DateTime<Utc>,
//     pub last_accessed: DateTime<Utc>,
//     pub last_written: DateTime<Utc>,
// }

/// Converts a &str to a wide OsStr (utf16)
fn to_wstring(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn open_file_by_id(frn: u64, volume_handle: HANDLE) -> HANDLE {
    unsafe {
        let mut u: FILE_ID_DESCRIPTOR_u = std::mem::zeroed::<FILE_ID_DESCRIPTOR_u>();
        let mut l: LARGE_INTEGER = std::mem::zeroed::<LARGE_INTEGER>();
        *l.QuadPart_mut() = frn as i64;
        *u.FileId_mut() = l;

        let mut fid: FILE_ID_DESCRIPTOR = FILE_ID_DESCRIPTOR {
            dwSize: mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: 0,
            u,
        };
        let fid_ptr: *mut FILE_ID_DESCRIPTOR = &mut fid;
        OpenFileById(
            volume_handle,
            fid_ptr,
            GENERIC_READ,
            FILE_SHARE_READ, // | FILE_SHARE_WRITE,
            ptr::null_mut(),
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    }
}
pub fn get_file_information(
    file_reference_number: u64,
    volume_handle: HANDLE,
) -> Result<FILE_INFORMATION, i32> {
    match open_file_by_id(file_reference_number, volume_handle) {
        INVALID_HANDLE_VALUE => {
            /* todo: check if bad handles are a problem */
            return Err(INVALID_HANDLE_VALUE as i32);
        }
        f_handle => {
            let mut file_info_by_handle: BY_HANDLE_FILE_INFORMATION =
                unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
            let file_info_ptr: *mut BY_HANDLE_FILE_INFORMATION = &mut file_info_by_handle;
            unsafe { GetFileInformationByHandle(f_handle, file_info_ptr) };

            let file_information = unsafe {
                std::mem::transmute::<BY_HANDLE_FILE_INFORMATION, FILE_INFORMATION>(*file_info_ptr)
            };

            unsafe { CloseHandle(f_handle) };

            /* todo: move this to impl fn for each kind of time
            let mut c_system_time: SYSTEMTIME = std::mem::zeroed::<SYSTEMTIME>();
            let mut system_time_ptr: *mut SYSTEMTIME = &mut c_system_time;
            FileTimeToSystemTime(&file_info_by_handle.ftCreationTime, system_time_ptr);
            file_info.created = Utc
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
            file_info.last_accessed = Utc
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
            file_info.last_written = Utc
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
            */
            return Ok(file_information);
        }
    }
}

fn enumerate_usn_data(volume_guid: String) -> Result<Vec<USN_RECORD>, i32> {
    let volume_handle = get_file_read_handle(&volume_guid).expect("somethin' ain't right");
    let mut file_info_records: Vec<FILE_INFORMATION> = Vec::with_capacity(524_288);
    let mut records: Vec<USN_RECORD> = Vec::with_capacity(524_288);
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
                        mft_eof = true;
                        continue;
                    }
                    e => return Err(e as i32),
                }
            }
        }

        input_buffer.StartFileReferenceNumber = unsafe { *(output_buffer.as_ptr() as *const u64) };

        while buffer_cursor < bytes_read as isize {
            let buffer_pointer = unsafe { output_buffer.as_ptr().offset(buffer_cursor) };
            let usn_record: USN_RECORD = unsafe {
                std::mem::transmute::<[u8; USN_RECORD_LENGTH], USN_RECORD>(
                    std::slice::from_raw_parts(buffer_pointer, USN_RECORD_LENGTH)
                        .try_into()
                        .expect("try_into #2 failed"),
                )
            };

            // move the cursor to the start of the next record
            buffer_cursor = buffer_cursor + (usn_record.RecordLength as isize);

            if usn_record.is_file() {
                match get_file_information(usn_record.FileReferenceNumber, volume_handle) {
                    Ok(file_info) => {
                        if usn_record.ParentFileReferenceNumber == 0 {
                            dbg!(
                                usn_record.file_name(),
                                file_info.creation_time(),
                                file_info.last_access_time(),
                                file_info.last_write_time()
                            );
                        }
                        file_info_records.push(file_info);
                    }
                    Err(_) => {}
                }
            }

            records.push(usn_record);
        }
    }
    unsafe { CloseHandle(volume_handle) };
    Ok(records)
}

fn read_file_usn_data(file: &str) -> Result<USN_RECORD, i32> {
    let file_handle = get_file_read_handle(file).expect("can't get a handle on it");
    let mut output_buffer = [0u8; 1024]; // data out from DeviceIoControl()
    let mut bytes_read: u32 = 0;

    // https://github.com/forensicmatt/RsWindowsThingies/blob/e9bbb44130fb54eb38c39f88082f33b5c86b9196/src/usn/winioctrl.rs#L75
    if unsafe {
        DeviceIoControl(
            file_handle,
            FSCTL_READ_FILE_USN_DATA,
            //&mut input_buffer.StartFileReferenceNumber as *mut _ as *mut c_void, // what does this mean?
            ptr::null_mut(),
            0,
            output_buffer.as_mut_ptr() as *mut USN_RECORD as LPVOID,
            output_buffer.len() as DWORD,
            &mut bytes_read as LPDWORD,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(unsafe { GetLastError() } as i32);
    }
    unsafe { CloseHandle(file_handle) };

    let buffer_offset = 8;
    let buffer_pointer = unsafe { output_buffer.as_ptr().offset(buffer_offset) };
    let usn_record: USN_RECORD = unsafe {
        std::mem::transmute::<[u8; USN_RECORD_LENGTH], USN_RECORD>(
            std::slice::from_raw_parts(buffer_pointer, USN_RECORD_LENGTH)
                .try_into()
                .expect("try_into #2 failed"),
        )
    };

    Ok(usn_record)
}

/// walk the master file table (MFT)
pub fn read_mft(volume_root_guid: &str) -> Result<Vec<USN_RECORD>, i32> {
    let mut volume_guid = volume_root_guid.clone().to_string();
    volume_guid.truncate(volume_guid.len() - 1);
    match enumerate_usn_data(volume_guid) {
        Ok(mut records) => {
            // get the usn_record for the volume root directory so we know the top of our tree
            // ParentFileReferenceNumber will be 0
            match read_file_usn_data(volume_root_guid) {
                Ok(root_file_info) => {
                    records.push(root_file_info);
                }
                Err(e) => {
                    println!("error from read_file_usn_data {}", e);
                }
            }

            dbg!(
                records.len(),
                records.capacity(),
                std::mem::size_of::<USN_RECORD>(),
                (records.len() * std::mem::size_of::<USN_RECORD>()),
                (records.capacity() * std::mem::size_of::<USN_RECORD>())
            );

            Ok(records)
        }
        Err(e) => Err(e),
    }
}

/* probably will throw away
fn get_directory_size(frn: u64, records: &Vec<FileInfo>) -> u64 {
    let size: u64 = records
        .iter()
        .filter(|x| {
            x.parent_reference_number == frn && x.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        })
        .map(|x| x.size_bytes)
        .sum();
    // for child_item in records.iter().filter(|x| x.parent_reference_number == frn) {
    //     if child_item.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
    //         size += get_directory_size(child_item.reference_number, records);
    //     } else {
    //         size += child_item.size_bytes;
    //     }
    // }
    size
}
*/

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
pub fn get_file_read_handle(file: &str) -> Result<HANDLE, i32> {
    let handle = unsafe {
        CreateFileW(
            to_wstring(file).as_ptr(),
            GENERIC_READ,
            // opening with FILE_SHARE_READ only gives a ERROR_SHARING_VIOLATION error
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, // required to get handle for directory
            // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#directories
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(unsafe { GetLastError() } as i32);
    }
    Ok(handle)
}

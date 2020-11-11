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
#[repr(C)]
struct MFT_ENUM_DATA_V0 {
    StartFileReferenceNumber: DWORDLONG,
    LowUsn: USN,
    HighUsn: USN,
}

#[repr(C, packed)]
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
    pub FileName: Vec<u8>,
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
    let mut output_buffer = [0u8; 1024 * 64]; // data out from DeviceIoControl()
    let mut input_buffer = MFT_ENUM_DATA_V0 {
        // into DeviceIoControl()
        StartFileReferenceNumber: 0,
        LowUsn: 0,
        HighUsn: i64::MAX,
    };

    for looped in 0..=500 {
        let mut buffer_cursor: usize = 8;
        unsafe {
            let mut bytes_read: u32 = 0;
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
                println!("DeviceIoControl failed. Error {}", GetLastError());
                std::process::exit(GetLastError() as i32);
            }

            while buffer_cursor < bytes_read as usize {
                println!("\n\n===================");
                println!("\nloop #: {}", looped);
                println!("buffer_cursor = {}", buffer_cursor);
                println!("bytes_read {}", bytes_read);

                let mut record_length = [0u8; 4];
                // record_length 4 bytes, [0..4]
                record_length
                    .clone_from_slice(&output_buffer[buffer_cursor + 0..buffer_cursor + 4]);

                println!(
                    "current StartFileReferenceNumber = {}",
                    input_buffer.StartFileReferenceNumber
                );

                let mut next = [0u8; 8]; //output_buffer[0..8]
                next.clone_from_slice(&output_buffer[0..8]);
                input_buffer.StartFileReferenceNumber = u64::from_le_bytes(next) as DWORDLONG;
                //u32::from_le_bytes(record_length) as DWORDLONG;
                println!(
                    "next StartFileReferenceNumber = {}",
                    input_buffer.StartFileReferenceNumber
                );

                println!(
                    "record_length = {}, {} bytes, {:?}",
                    u32::from_le_bytes(record_length),
                    record_length.len(),
                    record_length
                );

                // 2 bytes
                let mut major_version = [0u8; 2];
                major_version
                    .clone_from_slice(&output_buffer[buffer_cursor + 4..buffer_cursor + 6]);
                println!(
                    "major_version {}, {} bytes, {:?}",
                    u16::from_le_bytes(major_version),
                    major_version.len(),
                    major_version
                );
                let mut minor_version = [0u8; 2];
                minor_version
                    .clone_from_slice(&output_buffer[buffer_cursor + 6..buffer_cursor + 8]);
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
                // security_id 4 bytes, [48..52]
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
                if u16::from_le_bytes(file_name_length) > 0 {
                    println!("************************");
                    let mut file_name: Vec<u8> = Vec::new();
                    let file_name_start = (60 + file_name_offset_u16) as usize;
                    let file_name_end = file_name_start + file_name_length_u16 as usize;
                    println!(
                        "{}",
                        String::from_utf8_lossy(&output_buffer[file_name_start..file_name_end])
                    );
                    println!("************************");
                }

                // move the cursor to the start of the next record
                println!(
                    "u32::from_le_bytes(record_length) as usize = {}",
                    u32::from_le_bytes(record_length) as usize
                );
                buffer_cursor = buffer_cursor
                    + 60
                    + (u16::from_le_bytes(file_name_offset) as usize)
                    + (u16::from_le_bytes(file_name_length) as usize);
                println!("buffer_cursor = {}", buffer_cursor);
                //std::process::exit(42);
            }
            /* ========================================================
                        // for i in 0..body.len() {
                        //     println!(
                        //         "\n---\nbody[{}] size_of_val = {}",
                        //         i,
                        //         std::mem::size_of_val(&body[i])
                        //     );
                        //     println!(
                        //         "gee whiz body[{}].RecordLength = {}, size_of_val = {}",
                        //         i,
                        //         &body[i].RecordLength,
                        //         std::mem::size_of_val(&body[i].RecordLength)
                        //     );
                        //     println!(
                        //         "gee whiz body[{}].MajorVersion = {}, size_of_val = {}",
                        //         i,
                        //         body[i].MajorVersion,
                        //         std::mem::size_of_val(&body[i].MajorVersion)
                        //     );
                        //     println!(
                        //         "gee whiz body[{}].MinorVersion = {}, size_of_val = {}",
                        //         i,
                        //         body[i].MinorVersion,
                        //         std::mem::size_of_val(&body[i].MinorVersion)
                        //     );
                        //     println!(
                        //         "gee whiz body[{}].Usn = {}, size_of_val = {}",
                        //         i,
                        //         body[i].Usn,
                        //         std::mem::size_of_val(&body[i].Usn)
                        //     );
                        //     println!(
                        //         "gee whiz body[{}].Reason = {}, size_of_val = {}",
                        //         i,
                        //         body[i].Reason,
                        //         std::mem::size_of_val(&body[i].Reason)
                        //     );
                        //     println!(
                        //         "gee whiz body[{}].FileNameOffset = {}, size_of_val = {}",
                        //         i,
                        //         body[i].FileNameOffset,
                        //         std::mem::size_of_val(&body[i].FileNameOffset)
                        //     );
                        //     println!(
                        //         "gee whiz body[{}].FileNameLength = {}, size_of_val = {}",
                        //         i,
                        //         body[i].FileNameLength,
                        //         std::mem::size_of_val(&body[i].FileNameLength)
                        //     );
                        //     if body[i].FileNameLength > 0 && body[i].FileNameOffset > 0 {
                        //         //let x = String::from_utf8(body[i].FileName.clone()).unwrap();
                        //         // let x = String::from_utf16_lossy(
                        //         //     &body[i].FileName[0..body[i].FileNameLength as usize],
                        //         // );
                        //         // println!(
                        //         //     "gee whiz body[{}].FileName = {}, size_of_value = {}",
                        //         //     i,
                        //         //     x,
                        //         //     std::mem::size_of_val(&x)
                        //         // );
                        //     }
                        // }
                        // println!(
                        //     "mem::size_of::<MFT_ENUM_DATA_V0>() as u32 = {:#?}",
                        //     mem::size_of::<MFT_ENUM_DATA_V0>() as u32
                        // );
                        // println!("output_buffer {:?}", output_buffer);

                        // println!("WORD length = {}", std::mem::size_of::<WORD>());
                        // println!("WCHAR length = {}", std::mem::size_of::<WCHAR>());
                        // println!("DWORD length = {}", std::mem::size_of::<DWORD>());
                        // println!("DWORDLONG length = {}", std::mem::size_of::<DWORDLONG>());
                        // println!(
                        //     "LARGE_INTEGER length = {}",
                        //     std::mem::size_of::<LARGE_INTEGER>()
                        // );

                        //println!("=============");
                        //let mut record_length = [0u8; 4];
                        //record_length.clone_from_slice(&output_buffer[0..4]);
                        //println!(
                        //    "record_length = {}, {} bytes, {:?}",
                        //    u32::from_be_bytes(record_length),
                        //    record_length.len(),
                        //    record_length
                        //);

                        //let mut major_version = [0u8; 2];
                        //major_version.clone_from_slice(&output_buffer[5..7]);
                        //println!(
                        //    "major_version {}, {} bytes",
                        //    u16::from_be_bytes(major_version),
                        //    major_version.len()
                        //);

                        //let mut minor_version = [0u8; 2];
                        //minor_version.clone_from_slice(&output_buffer[8..10]);
                        //println!(
                        //    "minor_version {}, {} bytes",
                        //    u16::from_be_bytes(minor_version),
                        //    minor_version.len()
                        //);

                        //let mut filename_length = [0u8; 2];
                        //filename_length.clone_from_slice(&output_buffer[67..69]);
                        //println!(
                        //    "filename_length {}, {} bytes",
                        //    u16::from_be_bytes(filename_length),
                        //    filename_length.len()
                        //);

                        //let mut filename = [0u8; 36];
                        //filename.clone_from_slice(&output_buffer[73..109]);
                        //let x = String::from_utf8(filename.to_vec()).unwrap();
                        //println!("filename {}\n{}", x, filename.len());
            */
            // typedef struct {
            //     DWORD         RecordLength;                  4 bytes [0..4]
            //     WORD          MajorVersion;                  2 bytes [5..7]
            //     WORD          MinorVersion;                  2 bytes [8..10]
            //     DWORDLONG     FileReferenceNumber;           8 bytes [11..19]
            //     DWORDLONG     ParentFileReferenceNumber;     8 bytes [20..28]
            //     USN           Usn;                           8 bytes [29..37]
            //     LARGE_INTEGER TimeStamp;                     8 bytes [38..46]
            //     DWORD         Reason;                        4 bytes [47..51]
            //     DWORD         SourceInfo;                    4 bytes [52..56]
            //     DWORD         SecurityId;                    4 bytes [57..61]
            //     DWORD         FileAttributes;                4 bytes [62..66]
            //     WORD          FileNameLength;                2 bytes [67..69]
            //     WORD          FileNameOffset;                2 bytes [70..72]
            //     WCHAR         FileName[1];                   ? bytes [73..73+FileNameLength]
            // } USN_RECORD_V2, *PUSN_RECORD_V2;
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

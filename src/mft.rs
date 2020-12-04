#[allow(unused_imports)]
use crate::file_record::{FileRecord, NtfsFileRecordHeader};
use crate::ntfs_attributes::{
    ntfs_file_name::NtfsFileNameAttribute,
    ntfs_standard_information::NtfsStandardInformationAttribute, NtfsAttributeHeader,
    NtfsAttributeUnion::*,
};
use crate::usn_record::{USN_RECORD, USN_RECORD_LENGTH};
use crate::utils::str_to_wstring;

use crate::file_record::NtfsFileRecord;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::io::Error;
use std::ptr;
use winapi::shared::minwindef::{DWORD, FILETIME, LPDWORD, LPVOID, MAX_PATH, WORD};
use winapi::um::fileapi::{
    CreateFileW, GetVolumeNameForVolumeMountPointW, BY_HANDLE_FILE_INFORMATION, OPEN_EXISTING,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::winbase::{
    FILE_ID_DESCRIPTOR_u, LookupPrivilegeValueW, OpenFileById, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_ID_DESCRIPTOR,
};
use winapi::um::winioctl::{
    FSCTL_ENUM_USN_DATA, FSCTL_GET_NTFS_FILE_RECORD, FSCTL_GET_NTFS_VOLUME_DATA,
    FSCTL_READ_FILE_USN_DATA, NTFS_FILE_RECORD_INPUT_BUFFER, NTFS_FILE_RECORD_OUTPUT_BUFFER,
    NTFS_VOLUME_DATA_BUFFER,
};
use winapi::um::winnt::{DWORDLONG, HANDLE, LARGE_INTEGER, TOKEN_PRIVILEGES, USN};
use winapi::um::winnt::{
    //FILE_ATTRIBUTE_ARCHIVE,
    FILE_ATTRIBUTE_DIRECTORY,
    FILE_READ_ATTRIBUTES,
    FILE_READ_EA,
    //FILE_ATTRIBUTE_NORMAL,
    //FILE_ATTRIBUTE_READONLY,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    // GENERIC_READ,
    SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES,
};

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
struct MFT_ENUM_DATA_V0 {
    StartFileReferenceNumber: DWORDLONG,
    LowUsn: USN,
    HighUsn: USN,
}

#[derive(Debug, Clone)]
pub struct MFT {
    root_dir_frn: u64,
    volume_handle: HANDLE,
    pub file_records: BTreeMap<u64, Vec<FileRecord>>,
}

impl MFT {
    pub fn new(label: &str) -> Result<MFT, Error> {
        match MFT::assert_security_privileges() {
            Ok(_) => {
                if let Some(r_guid) = MFT::get_volume_guid(label) {
                    if let Ok(root_usn) = MFT::get_file_usn(&r_guid) {
                        let mut v_guid = r_guid.clone().to_string();
                        v_guid.truncate(v_guid.len() - 1);
                        if let Ok(handle) = MFT::get_file_read_handle(&v_guid) {
                            return Ok(MFT {
                                root_dir_frn: root_usn.FileReferenceNumber,
                                volume_handle: handle,
                                file_records: BTreeMap::<u64, Vec<FileRecord>>::new(),
                            });
                        }
                    } else {
                        return Err(Error::last_os_error());
                    }
                } else {
                    return Err(Error::last_os_error());
                }
            }
            Err(e) => {
                dbg!(e);
            }
        }
        Err(Error::new(
            std::io::ErrorKind::Other,
            "could not create struct MFT",
        ))
    }

    pub fn get_record(&self, frn: u64) {
        match self.get_ntfs_file_record(frn) {
            Ok(record) => {
                //dbg!(record);
            }
            Err(e) => {
                unimplemented!()
            }
        }
    }
    pub fn get_all_ntfs_file_records(
        &self,
    ) -> Result<BTreeMap<u64, NtfsFileRecord>, std::io::Error> {
        let mut records: BTreeMap<u64, NtfsFileRecord> = BTreeMap::new();

        match MFT::get_all_file_usn(&self) {
            Ok(frns) => {
                for frn in frns {
                    let rec = self.get_ntfs_file_record(frn)?;
                    records.insert(frn, rec);
                }
            }
            Err(e) => unimplemented!(),
        }
        Ok(records)
    }
    /*
        MFT PRIVATE FUNCTIONS

    */

    fn get_ntfs_file_record(&self, frn: u64) -> Result<NtfsFileRecord, Error> {
        let frn_l = unsafe {
            let mut large_i: LARGE_INTEGER = std::mem::zeroed::<LARGE_INTEGER>();
            *large_i.QuadPart_mut() = frn as i64;
            large_i
        };

        let input_buffer: NTFS_FILE_RECORD_INPUT_BUFFER = NTFS_FILE_RECORD_INPUT_BUFFER {
            FileReferenceNumber: frn_l,
        };
        // todo how can I do this???
        //const FILE_RECORD_SIZE: usize = _get_ntfs_file_record_size(volume_handle).unwrap();
        const FILE_RECORD_SIZE: usize = 1119;
        let mut output_buffer = [0u8; FILE_RECORD_SIZE];
        let mut bytes_read = 0u32;
        match unsafe {
            DeviceIoControl(
                self.volume_handle,
                FSCTL_GET_NTFS_FILE_RECORD,
                &input_buffer as *const NTFS_FILE_RECORD_INPUT_BUFFER as LPVOID,
                std::mem::size_of::<NTFS_FILE_RECORD_INPUT_BUFFER>() as DWORD,
                output_buffer.as_mut_ptr() as *mut NTFS_FILE_RECORD_OUTPUT_BUFFER as LPVOID,
                output_buffer.len() as DWORD,
                &mut bytes_read as LPDWORD,
                ptr::null_mut(),
            )
        } {
            0 => {
                // todo handle error
                dbg!("error FSTCL_GET_NTFS_FILE_RECORD");
                let last_error = Error::last_os_error();
                dbg!(&last_error);
                Err(last_error)
            }
            _ => {
                let file_record = NtfsFileRecord::new(&output_buffer[12..])?;

                Ok(file_record)
            }
        }
    }

    fn get_all_file_usn(&self) -> Result<Vec<u64>, std::io::Error> {
        let mut file_reference_numbers: Vec<u64> = Vec::new();
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
                    self.volume_handle,
                    FSCTL_ENUM_USN_DATA,
                    &input_buffer as *const MFT_ENUM_DATA_V0 as LPVOID, // what does this mean?
                    std::mem::size_of::<MFT_ENUM_DATA_V0>() as DWORD,
                    output_buffer.as_mut_ptr() as *mut USN_RECORD as LPVOID,
                    output_buffer.len() as DWORD,
                    &mut bytes_read as LPDWORD,
                    ptr::null_mut(),
                ) == 0
                {
                    let last_error = std::io::Error::last_os_error();
                    match last_error.raw_os_error().unwrap() {
                        ERROR_HANDLE_EOF => {
                            mft_eof = true;
                            continue;
                        }
                        _ => return Err(last_error),
                    }
                }
            }

            input_buffer.StartFileReferenceNumber =
                unsafe { *(output_buffer.as_ptr() as *const u64) };

            while buffer_cursor < bytes_read as isize {
                let buffer_pointer = unsafe { output_buffer.as_ptr().offset(buffer_cursor) };
                let usn_record: &USN_RECORD = unsafe { std::mem::transmute(buffer_pointer) };

                file_reference_numbers.push(usn_record.FileReferenceNumber);
                // move the cursor to the start of the next record
                buffer_cursor = buffer_cursor + (usn_record.RecordLength as isize);
            }
        }
        Ok(file_reference_numbers)
    }
    fn get_file_usn(file: &str) -> Result<USN_RECORD, Error> {
        let file_handle = MFT::get_file_read_handle(file)?;
        let mut output_buffer = [0u8; 1024]; // data out from DeviceIoControl()
        let mut bytes_read: u32 = 0;

        // https://github.com/forensicmatt/RsWindowsThingies/blob/e9bbb44130fb54eb38c39f88082f33b5c86b9196/src/usn/winioctrl.rs#L75
        match unsafe {
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
        } {
            0 => Err(Error::last_os_error()),
            _ => {
                unsafe { CloseHandle(file_handle) };

                let buffer_offset = 8;
                let buffer_pointer = unsafe { output_buffer.as_ptr().offset(buffer_offset) };
                let usn_record: USN_RECORD = unsafe {
                    std::mem::transmute::<[u8; USN_RECORD_LENGTH], USN_RECORD>(
                        std::slice::from_raw_parts(buffer_pointer, USN_RECORD_LENGTH)
                            .try_into()
                            .expect("USN_RECORD transmute failed :`("),
                    )
                };

                Ok(usn_record)
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
    fn assert_security_privileges() -> Result<bool, Error> {
        let mut proc_token: HANDLE = ptr::null_mut();
        match unsafe {
            // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
            // https://github.com/ricostrong/mesosfuzz/blob/13c599f89610008f6cbfe953c0761dd472fe67e4/libs/debugger/src/sedebug.rs#L20
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES,
                &mut proc_token,
            )
        } {
            0 => {
                let last_error = Error::last_os_error();
                println!("OpenProcessToken error {}", &last_error); // GetLastError());
                println!(
                    "See https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes"
                );
                Err(last_error)
            }
            _ => {
                // Set privileges for the process
                let privileges: [&str; 2] = ["SeBackupPrivilege", "SeRestorePrivilege"];
                for i in 0..=1 {
                    let mut token_privileges: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };

                    // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
                    match unsafe {
                        LookupPrivilegeValueW(
                            ptr::null(),
                            str_to_wstring(privileges[i]).as_ptr(),
                            &mut token_privileges.Privileges[0].Luid,
                        )
                    } {
                        0 => {
                            let last_error = Error::last_os_error();
                            println!("LookupPrivilegeValueW error {}", last_error);
                            println!(
                                "See https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes"
                            );
                            return Err(last_error);
                        }
                        _ => {
                            token_privileges.PrivilegeCount = 1;
                            token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                        }
                    }

                    // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
                    match unsafe {
                        AdjustTokenPrivileges(
                            proc_token,
                            0,
                            &mut token_privileges,
                            0,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        )
                    } {
                        0 => {
                            let last_error = Error::last_os_error();
                            println!("AdjustTokenPrivileges failed, error {}", last_error);
                            println!(
                                    "Unable to adjust privileges. Be sure to run with elevated permissions."
                                );
                            return Err(last_error);
                        }
                        _ => {
                            let last_error = Error::last_os_error();
                            if last_error.raw_os_error().unwrap() == 1300
                            // ERROR_NOT_ALL_ASSIGNED
                            {
                                println!(
                                    "\n*** Unable to adjust privileges. Try running as an administrator. ***\n"
                                );
                                return Err(last_error);
                            };
                        }
                    }
                }
                // close our process token handle
                unsafe { CloseHandle(proc_token) };
                Ok(true)
            }
        }
    }

    /** get_volume_guid will get the unique volume name (GUID).

    Example return value:

    ```text
    \\?\Volume{6eb8a49a-0000-0000-0000-300300000000}\
    ```
    */
    pub fn get_volume_guid(drive: &str) -> Option<String> {
        let volume_guid = &mut [0; MAX_PATH + 1];
        match unsafe {
            GetVolumeNameForVolumeMountPointW(
                str_to_wstring(drive).as_ptr(),
                volume_guid.as_mut_ptr(),
                volume_guid.len() as u32,
            )
        } {
            1 => Some(String::from_utf16_lossy(
                &volume_guid[..volume_guid
                    .iter()
                    .position(|v| *v == 0)
                    .unwrap_or(volume_guid.len())],
            )),
            _ => None,
        }
    }

    /**
    Gets a handle to a volume using the volume GUID. Must be run with administrator privileges.

    _NOTE:_ the volume guid should __not__ have a trailing slash `\`. The trailing backslash
    points to the root directory of the volume instead of the volume itself.

    Example volume GUID: `\\?\Volume{6eb8a49a-0000-0000-0000-300300000000}`

    */
    fn get_file_read_handle(file: &str) -> Result<HANDLE, Error> {
        let handle = unsafe {
            CreateFileW(
                str_to_wstring(file).as_ptr(),
                FILE_READ_EA,
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
            return Err(Error::last_os_error());
        }

        Ok(handle)
    }
}

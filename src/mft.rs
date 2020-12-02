#[allow(unused_imports)]
use crate::file_record::{
    FileRecord, NtfsAttributeCommonHeader, NtfsFileRecordHeader,
    NTFS_ATTRIBUTE_COMMON_HEADER_LENGTH, NTFS_FILE_RECORD_HEADER_LENGTH,
};
use crate::str_to_wstring;
use crate::usn_record::{USN_RECORD, USN_RECORD_LENGTH};

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
        match MFT::get_ntfs_file_record(frn, self.volume_handle) {
            Ok(record) => {
                dbg!(record);
            }
            Err(e) => {
                dbg!(e);
            }
        }
    }
    /*
        MFT PRIVATE FUNCTIONS

    */

    fn get_ntfs_file_record(frn: u64, volume_handle: HANDLE) -> Result<FileRecord, Error> {
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
                volume_handle,
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
                // output is NTFS_FILE_RECORD_OUTPUT_BUFFER
                // https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_file_record_output_buffer
                //
                // typedef struct {
                //   LARGE_INTEGER FileReferenceNumber;
                //   DWORD         FileRecordLength;
                //   BYTE          FileRecordBuffer[1];
                // } NTFS_FILE_RECORD_OUTPUT_BUFFER, *PNTFS_FILE_RECORD_OUTPUT_BUFFER;
                //
                // output.FileRecordBuffer has the actual file record, but I am using the output_buffer
                // offset by 12 (8 for LARGE_INTEGER and 4 for DWORD) bytes to parse the record and loop
                // through attributes.
                //
                // For additional info see:
                // https://www.cse.scu.edu/~tschwarz/coen252_07Fall/Lectures/NTFS.html
                // https://flatcap.org/linux-ntfs/ntfs/concepts/file_record.html
                // https://flatcap.org/linux-ntfs/ntfs/concepts/attribute_header.html
                //

                let output = unsafe {
                    std::mem::transmute::<[u8; 16], NTFS_FILE_RECORD_OUTPUT_BUFFER>(
                        output_buffer[..16].try_into().expect("shit"),
                    )
                };

                // todo why don't these match? Should they? What gives, man?
                // dbg!(unsafe { frn.QuadPart() });
                // dbg!(unsafe { *output.FileReferenceNumber.QuadPart() });
                // dbg!(output.FileRecordLength);

                let file_record: Vec<u8> = output_buffer
                    [12..(output.FileRecordLength as usize + 12)]
                    .try_into()
                    .expect("you should handle this");

                let file_record_header = unsafe {
                    std::mem::transmute::<[u8; NTFS_FILE_RECORD_HEADER_LENGTH], NtfsFileRecordHeader>(
                        file_record[..NTFS_FILE_RECORD_HEADER_LENGTH]
                            .try_into()
                            .expect("you should handle this"),
                    )
                };
                dbg!(&file_record_header);

                let mut attributes: Vec<Vec<u8>> = Vec::new();
                let mut attribute_offset = file_record_header.attribute_offset as usize;
                loop {
                    let attribute_header = unsafe {
                        std::mem::transmute::<
                            [u8; NTFS_ATTRIBUTE_COMMON_HEADER_LENGTH],
                            NtfsAttributeCommonHeader,
                        >(
                            file_record[attribute_offset
                                ..attribute_offset + NTFS_ATTRIBUTE_COMMON_HEADER_LENGTH]
                                .try_into()
                                .expect("danger will robinson!"),
                        )
                    };
                    println!(
                        "\n*** Found attribute type {:#x} ***\n",
                        attribute_header.attribute_type
                    );

                    if attribute_header.attribute_type == 4294967295 {
                        // attribute list ends with type 0xFFFFFFFF
                        break;
                    }
                    attributes.push(
                        file_record[attribute_offset
                            ..attribute_offset + attribute_header.length_with_header as usize]
                            .try_into()
                            .expect("what am I doing"),
                    );

                    attribute_offset += attribute_header.length_with_header as usize;
                }

                // todo parse attributes in a nice way...
                dbg!(attributes.len());
                println!("\n\n\n");

                Ok(FileRecord::default())
            }
        }
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

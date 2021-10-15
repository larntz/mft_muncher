//
// see https://stackoverflow.com/questions/21661798/how-do-we-access-mft-through-c-sharp/45646777#45646777
// for an outline of what was implemented here.
//

extern crate winapi;

use self::winapi::um::winioctl::FSCTL_GET_NTFS_VOLUME_DATA;
use chrono::prelude::*;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::mem;
use std::ptr;
use winapi::_core::i64;
use winapi::shared::minwindef::{DWORD, FILETIME, LPDWORD, LPVOID, MAX_PATH, WORD};
use winapi::shared::winerror::ERROR_HANDLE_EOF;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::GetFileInformationByHandle;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::fileapi::{
    CreateFileW, GetVolumeNameForVolumeMountPointW, BY_HANDLE_FILE_INFORMATION,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::minwinbase::SYSTEMTIME;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::timezoneapi::FileTimeToSystemTime;
use winapi::um::winbase::{
    FILE_ID_DESCRIPTOR_u, LookupPrivilegeValueW, OpenFileById, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_ID_DESCRIPTOR,
};
use winapi::um::winioctl::{
    FSCTL_ENUM_USN_DATA, FSCTL_GET_NTFS_FILE_RECORD, FSCTL_READ_FILE_USN_DATA,
    NTFS_FILE_RECORD_INPUT_BUFFER, NTFS_FILE_RECORD_OUTPUT_BUFFER, NTFS_VOLUME_DATA_BUFFER,
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
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct USN_RECORD {
    RecordLength: DWORD,
    MajorVersion: WORD,
    MinorVersion: WORD,
    pub FileReferenceNumber: DWORDLONG,
    pub ParentFileReferenceNumber: DWORDLONG,
    Usn: USN,
    //TimeStamp: LARGE_INTEGER,
    //Reason: DWORD,
    //SourceInfo: DWORD,
    _invalid: [u8; 16], // previous 3 values are not valid
    SecurityId: DWORD,
    FileAttributes: DWORD,
    FileNameLength: WORD,
    FileNameOffset: WORD,
    FileName: [u16; 128],
}

impl USN_RECORD {
    pub fn file_name(&self) -> String {
        let filename = self.FileName.as_ptr();
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

    pub fn is_file(&self) -> bool {
        match self.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY {
            0 => true,
            _ => false,
        }
    }

    fn creation_time(&self) -> DateTime<Utc> {
        let mut system_time: SYSTEMTIME = unsafe { std::mem::zeroed::<SYSTEMTIME>() };
        let system_time_ptr: *mut SYSTEMTIME = &mut system_time;
        let result = unsafe { FileTimeToSystemTime(&self.ftCreationTime, system_time_ptr) };
        if result != 0 {
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
        } else {
            Utc.ymd(1970, 1, 1).and_hms(0, 0, 0)
        }
    }
    fn last_access_time(&self) -> DateTime<Utc> {
        let mut system_time: SYSTEMTIME = unsafe { std::mem::zeroed::<SYSTEMTIME>() };
        let system_time_ptr: *mut SYSTEMTIME = &mut system_time;
        let result = unsafe { FileTimeToSystemTime(&self.ftLastAccessTime, system_time_ptr) };

        if result != 0 {
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
        } else {
            Utc.ymd(1970, 1, 1).and_hms(0, 0, 0)
        }
    }
    fn last_write_time(&self) -> DateTime<Utc> {
        let mut system_time: SYSTEMTIME = unsafe { std::mem::zeroed::<SYSTEMTIME>() };
        let system_time_ptr: *mut SYSTEMTIME = &mut system_time;
        let result = unsafe { FileTimeToSystemTime(&self.ftLastWriteTime, system_time_ptr) };

        if result != 0 {
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
        } else {
            Utc.ymd(1970, 1, 1).and_hms(0, 0, 0)
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub file_name: String,
    pub frn: u64,
    pub parent_frn: Vec<u64>,
    pub child_frn: Vec<u64>,
    pub attributes: u32,
    pub allocated_size_bytes: u64,
    pub real_size_bytes: u64,
    created: u64,
    accessed: u64,
    written: u64,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub reference_number: u64,
    pub parent_reference_number: u64,
    pub attributes: u32,
    pub size_bytes: u64,
    pub created: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub last_written: DateTime<Utc>,
}

impl FileInfo {
    pub fn is_file(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    }
}

/// Converts a &str to a wide OsStr (utf16)
fn to_wstring(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn get_ntfs_volume_data(volume_handle: HANDLE) {
    const BUFFER_SIZE: usize = std::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>();
    let mut output_buffer = [0u8; BUFFER_SIZE];
    let mut bytes_read = 0u32;

    match unsafe {
        DeviceIoControl(
            volume_handle,
            FSCTL_GET_NTFS_VOLUME_DATA,
            ptr::null_mut(),
            0,
            output_buffer.as_mut_ptr() as *mut NTFS_VOLUME_DATA_BUFFER as LPVOID,
            output_buffer.len() as DWORD,
            &mut bytes_read,
            ptr::null_mut(),
        )
    } {
        0 => { /* error */ }
        _ => {
            let volume_data = unsafe {
                std::mem::transmute::<[u8; BUFFER_SIZE], NTFS_VOLUME_DATA_BUFFER>(output_buffer)
            };
            dbg!(bytes_read);
            dbg!(volume_data.BytesPerFileRecordSegment);
            dbg!(unsafe { volume_data.VolumeSerialNumber.QuadPart() });
            let size_of_file_record = mem::size_of::<NTFS_VOLUME_DATA_BUFFER>()
                + (volume_data.BytesPerFileRecordSegment as usize)
                - 1;
            dbg!(size_of_file_record);
        }
    }
}

fn get_time_from_filetime(file_time: u64) -> DateTime<Utc> {
    let mut filetime: FILETIME = unsafe { std::mem::zeroed::<FILETIME>() };
    filetime.dwLowDateTime = file_time as DWORD;
    filetime.dwHighDateTime = (file_time >> 32) as DWORD;

    let ftime: *const FILETIME = &mut filetime;
    let mut system_time: SYSTEMTIME = unsafe { std::mem::zeroed::<SYSTEMTIME>() };
    let system_time_ptr: *mut SYSTEMTIME = &mut system_time;
    let result = unsafe { FileTimeToSystemTime(ftime, system_time_ptr) };
    if result != 0 {
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
    } else {
        Utc.ymd(1970, 1, 1).and_hms(0, 0, 0)
    }
}

// ntfs_record
// todo read ntfs file records
// try to calculate sizes from this...
// should fix the problem getting handles on individual files and maybe speed things up.
fn get_ntfs_file_record(frn: u64, volume_handle: HANDLE) {
    let frn = unsafe {
        let mut large_i: LARGE_INTEGER = std::mem::zeroed::<LARGE_INTEGER>();
        *large_i.QuadPart_mut() = frn as i64;
        large_i
    };

    let input_buffer: NTFS_FILE_RECORD_INPUT_BUFFER = NTFS_FILE_RECORD_INPUT_BUFFER {
        FileReferenceNumber: frn,
    };

    let mut output_buffer = [0u8; 1119];
    let mut bytes_read = 0u32;
    match unsafe {
        DeviceIoControl(
            volume_handle,
            FSCTL_GET_NTFS_FILE_RECORD,
            &input_buffer as *const NTFS_FILE_RECORD_INPUT_BUFFER as LPVOID,
            mem::size_of::<NTFS_FILE_RECORD_INPUT_BUFFER>() as DWORD,
            output_buffer.as_mut_ptr() as *mut NTFS_FILE_RECORD_OUTPUT_BUFFER as LPVOID,
            output_buffer.len() as DWORD,
            &mut bytes_read as LPDWORD,
            ptr::null_mut(),
        )
    } {
        0 => {
            // todo handle error
            dbg!("error FSTCL_GET_NTFS_FILE_RECORD");
            dbg!(unsafe { GetLastError() as i32 });
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
            dbg!(unsafe { frn.QuadPart() });
            dbg!(unsafe { *output.FileReferenceNumber.QuadPart() });
            dbg!(output.FileRecordLength);

            let file_record: Vec<u8> = output_buffer[12..(output.FileRecordLength as usize + 12)]
                .try_into()
                .expect("asdf");
            dbg!(file_record.len());
            assert_eq!(output.FileRecordLength as usize, file_record.len());

            let mut magic: [u8; 4] = Default::default();
            magic.copy_from_slice(&file_record[..4]);
            // verify the first 4 bytes == 'FILE'
            assert_eq!(magic, [70, 73, 76, 69,]);
            println!("\n\n-----\nmagic number {:?}", magic);

            let offset_to_usn: usize =
                u16::from_le_bytes(file_record[0x04..0x06].try_into().expect("byte me")) as usize;
            println!(
                "\toffset to the update sequence: {:#x} ({})",
                offset_to_usn, offset_to_usn
            );

            let update_sequence_array_size =
                u16::from_le_bytes(file_record[0x06..0x08].try_into().expect("byte me"));

            println!(
                "\tsize in words of the update sequence {} ( size == 2 * update_sequence_array_size - 2 == {})",
                update_sequence_array_size,
                2 * update_sequence_array_size - 2,
            );

            let sequence_number =
                u16::from_le_bytes(file_record[0x10..0x12].try_into().expect("byte me"));
            println!("\tsequence number {}", sequence_number);

            let hard_link_count =
                u16::from_le_bytes(file_record[0x12..0x14].try_into().expect("byte me"));
            println!("\thard link count {}", hard_link_count);

            let mut attribute_offset =
                u16::from_le_bytes(file_record[0x14..0x16].try_into().expect("byte me")) as usize;
            println!("\toffset of first attribute {:#x}", attribute_offset,);

            let flags = u16::from_le_bytes(file_record[0x16..0x18].try_into().expect("byte me"));
            println!("\tflags {:#x} (0x01 == in use, 0x02 == directory", flags);

            /* not needed for my purposes
            dbg!(
                "real size of file record",
                u32::from_le_bytes(file_record[0x18..0x18 + 4].try_into().expect("byte me"))
            );
            dbg!(
                "allocated size of file record",
                u32::from_le_bytes(file_record[0x1c..0x1c + 4].try_into().expect("byte me"))
            );
            */

            let base_record_frn =
                u64::from_le_bytes(file_record[0x20..0x28].try_into().expect("byte me"));
            println!("\tfrn to the base FILE record {}", base_record_frn);

            let update_sequence_number: [u8; 2] = file_record[offset_to_usn..offset_to_usn + 2]
                .try_into()
                .expect("byte me");
            println!(
                "\tupdate sequence number {}",
                u16::from_le_bytes(update_sequence_number),
            );

            let usa_len = 2 * update_sequence_array_size - 2;
            let usa: Vec<u8> = Vec::from(&file_record[0x32..0x32 + usa_len as usize]);
            println!("\tupdate sequence array {:?}", usa);

            let mut attribute_eof = false;
            while !attribute_eof && attribute_offset < file_record.len() {
                println!("\t-----");
                let start_rec = attribute_offset as usize;

                let offset = start_rec;
                let attribute_type = u32::from_le_bytes(
                    file_record[offset..offset + 4].try_into().expect("byte me"),
                );
                println!("\t\tattribute type {:#x}", attribute_type);
                // attribute list is terminated with 0xffffffff
                if attribute_type == 0xffffffff {
                    attribute_eof = true;
                    continue;
                }

                let offset = start_rec + 0x08;
                let attribute_resident =
                    u8::from_le_bytes(file_record[offset..offset + 1].try_into().expect("byte me"));
                println!(
                    "\t\tattribute resident flag {:#x} (0x0 == resident, 0x1 == non-resident",
                    attribute_resident
                );

                let offset = start_rec + 0x04; // length offset is 0x04
                let attribute_length_header = u32::from_le_bytes(
                    file_record[offset..offset + 4].try_into().expect("byte me"),
                ) as usize;
                println!(
                    "\t\tattribute length (incl. header) {}",
                    attribute_length_header
                );

                // add to get the start of the next attribute record
                attribute_offset += attribute_length_header;

                let offset = start_rec + 0x09;
                let attribute_name_length =
                    u8::from_le_bytes(file_record[offset..offset + 1].try_into().expect("byte me"));
                println!("\t\tattribute name length {}", attribute_name_length);

                let offset = start_rec + 0x0a;
                let attribute_name_offset = u16::from_le_bytes(
                    file_record[offset..offset + 2].try_into().expect("byte me"),
                );
                println!("\t\tattribute name offset {:#x}", attribute_name_offset);

                let offset = start_rec + 0x0c;
                let attribute_flags = u16::from_le_bytes(
                    file_record[offset..offset + 2].try_into().expect("byte me"),
                );
                println!("\t\tattribute flags {:#x}", attribute_flags);

                let offset = start_rec + 0x0e;
                let attribute_identifier = u16::from_le_bytes(
                    file_record[offset..offset + 2].try_into().expect("byte me"),
                );
                println!("\t\tattribute identifier {:#x}", attribute_identifier);

                if attribute_resident == 0x0 {
                    let offset = start_rec + 0x10;
                    let attribute_length = u32::from_le_bytes(
                        file_record[offset..offset + 4].try_into().expect("byte me"),
                    );
                    println!("\t\tattribute length {} bytes", attribute_length);

                    let offset = start_rec + 0x14;
                    let attribute_content_offset = u16::from_le_bytes(
                        file_record[offset..offset + 2].try_into().expect("byte me"),
                    );
                    println!("\t\tcontent offset {:#x}", attribute_content_offset);
                    println!(" ");

                    let offset = start_rec + attribute_content_offset as usize;
                    match attribute_type {
                        0x10 => {
                            // parsing the $STANDARD_INFORMATION attribute for file times and flags
                            // flags are read-only, hidden, etc.
                            // https://flatcap.org/linux-ntfs/ntfs/attributes/standard_information.html

                            // create time
                            let time = u64::from_le_bytes(
                                file_record[offset..offset + 8].try_into().expect("byte me"),
                            );
                            let time = get_time_from_filetime(time);
                            println!("\t\tcreate time: {}", time);

                            let offset = start_rec + attribute_content_offset as usize + 0x08;
                            // modified time
                            let time = u64::from_le_bytes(
                                file_record[offset..offset + 8].try_into().expect("byte me"),
                            );
                            let time = get_time_from_filetime(time);
                            println!("\t\tmodified time: {}", time);

                            let offset = start_rec + attribute_content_offset as usize + 0x18;
                            // read time
                            let time = u64::from_le_bytes(
                                file_record[offset..offset + 8].try_into().expect("byte me"),
                            );
                            let time = get_time_from_filetime(time);
                            println!("\t\tread time: {}", time);

                            let offset = start_rec + attribute_content_offset as usize + 0x20;
                            let file_flags = u32::from_le_bytes(
                                file_record[offset..offset + 4].try_into().expect("byte me"),
                            );
                            println!("\t\tfile flags {:#x}", file_flags);
                        }
                        0x30 => {
                            // parsing the $FILE_NAME attribute
                            // will use file reference to parent directory to track hard links and reparse? points
                            //
                            // https://flatcap.org/linux-ntfs/ntfs/attributes/file_name.html
                            //
                            // N.B. All fields, except the parent directory, are only updated when
                            // the filename is changed. Until then, they just become out of date.
                            // $STANDARD_INFORMATION Attribute, however, will always be kept up-to-date.
                            let parent_ref = u64::from_le_bytes(
                                file_record[offset..offset + 8].try_into().expect("byte me"),
                            );
                            println!("\t\tfile parent ref: {}", parent_ref);

                            let offset = start_rec + attribute_content_offset as usize + 0x38;
                            let file_name_flags = u32::from_le_bytes(
                                file_record[offset..offset + 4].try_into().expect("byte me"),
                            );
                            println!("\t\tfile name flags: {:#x}", file_name_flags);

                            let offset = start_rec + attribute_content_offset as usize + 0x40;
                            let file_name_length = u8::from_le_bytes(
                                file_record[offset..offset + 1].try_into().expect("byte me"),
                            );
                            println!("\t\tfile name length {}", file_name_length);

                            let offset = start_rec + attribute_content_offset as usize + 0x41;
                            let file_namespace = u8::from_le_bytes(
                                file_record[offset..offset + 1].try_into().expect("byte me"),
                            );
                            println!(
                                "\t\tfile namespace {} ( 0 posix, 1 win32, 2 dos, 3 win32 & dos)",
                                file_namespace
                            );

                            let offset = start_rec + attribute_content_offset as usize + 0x42;
                            let filename_slice: Vec<u8> = file_record
                                [offset..offset + (2 * file_name_length as usize)]
                                .try_into()
                                .expect("byte me");
                            println!("\t\tname = {}", String::from_utf8_lossy(&filename_slice));
                        }
                        _ => {}
                    }
                } else {
                    let offset = start_rec + 0x28;
                    // allocated = size on disk (real size rounded up to nearest cluster)
                    let allocated_attribute_length = u32::from_le_bytes(
                        file_record[offset..offset + 4].try_into().expect("byte me"),
                    );
                    println!(
                        "\t\tallocated attribute length {}, {} kb",
                        allocated_attribute_length,
                        allocated_attribute_length / 1024
                    );

                    // real size of data (<= allocated size)
                    let offset = start_rec + 0x30;
                    let real_attribute_length = u32::from_le_bytes(
                        file_record[offset..offset + 4].try_into().expect("byte me"),
                    );
                    println!(
                        "\t\treal attribute length {}, {} kb",
                        real_attribute_length,
                        real_attribute_length / 1024
                    );
                }
            }
            println!("\n\n{:?}", file_record);
        }
    }
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
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            ptr::null_mut(),
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    }
}
pub fn get_file_information(
    file_reference_number: u64,
    volume_handle: HANDLE,
) -> Result<FILE_INFORMATION, i32> {
    return match open_file_by_id(file_reference_number, volume_handle) {
        INVALID_HANDLE_VALUE => {
            /* todo: check if bad handles are a problem */
            Err(unsafe { GetLastError() } as i32)
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

            Ok(file_information)
        }
    };
}

fn enumerate_usn_data(volume_guid: String) -> Result<BTreeMap<u64, Vec<FileInfo>>, i32> {
    let volume_handle = get_file_read_handle(&volume_guid).expect("somethin' ain't right");
    let mut records: BTreeMap<u64, Vec<FileInfo>> = BTreeMap::new();
    let mut output_buffer = [0u8; 1024 * 128]; // data out from DeviceIoControl()
    let mut input_buffer = MFT_ENUM_DATA_V0 {
        // into DeviceIoControl()
        StartFileReferenceNumber: 0,
        LowUsn: 0,
        HighUsn: i64::MAX,
    };
    let mut mft_eof: bool = false;

    let mut invalid_handles = 0u32;
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
                    ERROR_HANDLE_EOF => {
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
            let usn_record: &USN_RECORD = unsafe {
                std::mem::transmute::<[u8; USN_RECORD_LENGTH], &USN_RECORD>(
                    std::slice::from_raw_parts(buffer_pointer, USN_RECORD_LENGTH)
                        .try_into()
                        .expect("try_into #2 failed"),
                )
            };

            // move the cursor to the start of the next record
            buffer_cursor = buffer_cursor + (usn_record.RecordLength as isize);

            // testing
            if usn_record.file_name() == "basebrd.dll" {
                dbg!(usn_record);
                dbg!(usn_record.file_name());
                println!("calling get ntfs volume data");
                get_ntfs_volume_data(volume_handle);
                println!("calling get ntfs file record");
                get_ntfs_file_record(usn_record.FileReferenceNumber, volume_handle);
                //std::process::exit(42);
            }

            // get FILE_INFORMATION
            match get_file_information(usn_record.FileReferenceNumber, volume_handle) {
                Ok(file_info) => {
                    //todo how to deal with files that have > 1 links?
                    // if usn_record.FileReferenceNumber == 281474976739376 {
                    //     println!(
                    //         "{} has {} links",
                    //         usn_record.file_name(),
                    //         file_info.nNumberOfLinks
                    //     );
                    // }
                    if let Some(value) = records.get_mut(&usn_record.ParentFileReferenceNumber) {
                        value.push(FileInfo {
                            name: usn_record.file_name(),
                            reference_number: usn_record.FileReferenceNumber,
                            parent_reference_number: usn_record.ParentFileReferenceNumber,
                            attributes: file_info.dwFileAttributes,
                            size_bytes: if file_info.is_file() {
                                file_info.file_size()
                            } else {
                                0
                            },
                            created: file_info.creation_time(),
                            last_accessed: file_info.last_access_time(),
                            last_written: file_info.last_write_time(),
                        });
                    } else {
                        records.insert(
                            usn_record.ParentFileReferenceNumber,
                            vec![FileInfo {
                                name: usn_record.file_name(),
                                reference_number: usn_record.FileReferenceNumber,
                                parent_reference_number: usn_record.ParentFileReferenceNumber,
                                attributes: file_info.dwFileAttributes,
                                size_bytes: if file_info.is_file() {
                                    file_info.file_size()
                                } else {
                                    0
                                },
                                created: file_info.creation_time(),
                                last_accessed: file_info.last_access_time(),
                                last_written: file_info.last_write_time(),
                            }],
                        );
                    }
                }
                Err(_e) => {
                    // todo check for INVALID_FILE_HANDLE or a different error
                    // println!(
                    //     "error on file {}, {} [{}\\{}]",
                    //     usn_record.file_name(),
                    //     e,
                    //     usn_record.ParentFileReferenceNumber,
                    //     usn_record.FileReferenceNumber
                    // );
                    invalid_handles += 1;
                }
            }
        }
    }
    dbg!(invalid_handles);
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
pub fn read_mft(volume_root_guid: &str) -> Result<BTreeMap<u64, Vec<FileInfo>>, i32> {
    let mut volume_guid = volume_root_guid.clone().to_string();
    volume_guid.truncate(volume_guid.len() - 1);
    match enumerate_usn_data(volume_guid.clone()) {
        Ok(mut records) => {
            // get the usn_record for the volume root directory so we know the top of our tree
            // ParentFileReferenceNumber will be 0
            match read_file_usn_data(volume_root_guid) {
                Ok(root_file_usn) => {
                    let root_file_info = get_file_information(
                        root_file_usn.FileReferenceNumber,
                        get_file_read_handle(&volume_guid).unwrap(),
                    )
                    .unwrap();
                    records.insert(
                        0, // set this to be zero so we know it's the root
                        vec![FileInfo {
                            name: root_file_usn.file_name(),
                            reference_number: root_file_usn.FileReferenceNumber,
                            parent_reference_number: 0, // set this to be 0 so we know it's the root
                            attributes: root_file_info.dwFileAttributes,
                            size_bytes: 0,
                            created: root_file_info.creation_time(),
                            last_accessed: root_file_info.last_access_time(),
                            last_written: root_file_info.creation_time(),
                        }],
                    );
                    calculate_dir_sizes(&mut records);
                }
                Err(e) => {
                    println!("error from read_file_usn_data {}", e);
                }
            }

            Ok(records)
        }
        Err(e) => Err(e),
    }
}

fn calculate_dir_sizes(fs_tree: &mut BTreeMap<u64, Vec<FileInfo>>) {
    let mut frn_sizes: BTreeMap<u64, u64> = BTreeMap::new();
    let mut x = 0u64;
    for item in fs_tree.iter() {
        for child in item.1.iter().filter(|x| x.is_file() == false) {
            x += 1;
            let size = get_size(child.reference_number, &fs_tree);
            frn_sizes.insert(child.reference_number, size);
        }
    }
    dbg!(x);
    dbg!(&frn_sizes.len());
    for item in fs_tree.iter_mut() {
        for child in item.1.iter_mut().filter(|x| x.is_file() == false) {
            child.size_bytes = frn_sizes.get(&child.reference_number).unwrap().clone();
        }
    }
}
pub fn get_size(frn: u64, fs_tree: &BTreeMap<u64, Vec<FileInfo>>) -> u64 {
    // all non-empty directories should be parents and should be a key in `fs_tree`
    // we will recursively add child file sizes and return that.
    // if it isn't a key then it is an empty directory and the size is 0

    // todo we aren't getting all directory sizes here.... if a directory only contains directories
    // then we are getting 0... why?
    let mut size = 0u64;
    match fs_tree.get(&frn) {
        Some(item) => {
            for child in item {
                if child.is_file() {
                    size += child.size_bytes;
                } else {
                    size += get_size(child.reference_number, &fs_tree);
                }
            }
        }
        None => {
            //panic!("no entry {}", frn);
        }
    };
    size
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
pub fn get_file_read_handle(file: &str) -> Result<HANDLE, i32> {
    let handle = unsafe {
        CreateFileW(
            to_wstring(file).as_ptr(),
            //GENERIC_READ,
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
        return Err(unsafe { GetLastError() } as i32);
    }
    Ok(handle)
}

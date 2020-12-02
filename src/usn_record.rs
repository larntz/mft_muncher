use winapi::shared::minwindef::{DWORD, FILETIME, WORD};
use winapi::um::winnt::{DWORDLONG, USN};

// https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
pub const USN_RECORD_LENGTH: usize = 320; // size of USN_RECORD in bytes

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

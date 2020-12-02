mod ntfs_standard_attribute;
use ntfs_standard_attribute::*;

pub const NTFS_ATTRIBUTE_COMMON_HEADER_LENGTH: usize = 16;
#[derive(Debug)]
#[repr(C)]
pub struct NtfsAttributeCommonHeader {
    pub attribute_type: u32,
    pub length_with_header: u32,
    pub non_resident_flag: u8,
    pub name_length: u8,
    pub name_offset: u16,
    pub flags: u16,
    pub standard_attribute: NtfsStandardAttribute,
}

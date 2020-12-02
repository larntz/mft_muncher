#[derive(Debug, Clone, Default)]
pub struct FileRecord {
    pub file_name: String,
    pub frn: u64,
    pub parent_links: Vec<u64>,
    pub attributes: u32,
    pub allocated_size_bytes: u32,
    pub real_size_bytes: u32,
    pub created: u64,
    pub accessed: u64,
    pub written: u64,
}

pub const NTFS_FILE_RECORD_HEADER_LENGTH: usize = 48;
#[derive(Debug)]
#[repr(C)]
pub struct NtfsFileRecordHeader {
    pub magic_number: u32,
    pub update_sequence_offset: u16,
    pub update_sequence_size: u16, // size in words not bytes!!
    pub logfile_sequence_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub attribute_offset: u16,
    pub flags: u16,
    pub real_record_size: u32,
    pub allocated_record_size: u32,
    pub base_frn: u64,
    pub next_attribute_id: u16,
    pub align_4_byte: u16,
    pub mft_record_number: u32,
}

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
}

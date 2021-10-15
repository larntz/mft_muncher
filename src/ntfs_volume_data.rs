use crate::utils::*;

/// See [MS documentation](https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_volume_data_buffer) for details.
#[derive(Debug, Clone)]
pub struct NtfsVolumeData {
    pub volume_serial_number: u64, // 0x00 NOTE: MS docs show this as a LONG_INTEGER, and it appears to only use the bottom 4 bytes.
    pub number_sectors: i64,       // 0x08
    pub total_clusters: i64,       // 0x10
    pub free_clusters: i64,        // 0x18
    pub total_reserved: i64,       // 0x20
    pub bytes_per_sector: u32,     // 0x28
    pub bytes_per_cluster: u32,    // 0x2c
    pub bytes_per_file_record_segment: u32, // 0x30
    pub clusters_per_file_record_segment: u32, // 0x34
    pub mft_valid_data_length: i64, // 0x38
    pub mft_start_lcn: i64,        // 0x40
    pub mft2_start_lcn: i64,       // 0x48
    pub mft_zone_start: i64,       // 0x50
    pub mft_zone_end: i64,         // 0x58
    pub ntfs_extended_volume_information: Option<NtfsExtendedVolumeData>,
}
impl NtfsVolumeData {
    pub fn new(bytes: &[u8], extended: bool) -> Result<NtfsVolumeData, std::io::Error> {
        Ok(NtfsVolumeData {
            volume_serial_number: u64::from_le_bytes(get_bytes_8(&bytes[0x00..])?),
            number_sectors: i64::from_le_bytes(get_bytes_8(&bytes[0x08..])?),
            total_clusters: i64::from_le_bytes(get_bytes_8(&bytes[0x10..])?),
            free_clusters: i64::from_le_bytes(get_bytes_8(&bytes[0x18..])?),
            total_reserved: i64::from_le_bytes(get_bytes_8(&bytes[0x20..])?),
            bytes_per_sector: u32::from_le_bytes(get_bytes_4(&bytes[0x28..])?),
            bytes_per_cluster: u32::from_le_bytes(get_bytes_4(&bytes[0x2c..])?),
            bytes_per_file_record_segment: u32::from_le_bytes(get_bytes_4(&bytes[0x30..])?),
            clusters_per_file_record_segment: u32::from_le_bytes(get_bytes_4(&bytes[0x34..])?),
            mft_valid_data_length: i64::from_le_bytes(get_bytes_8(&bytes[0x38..])?),
            mft_start_lcn: i64::from_le_bytes(get_bytes_8(&bytes[0x40..])?),
            mft2_start_lcn: i64::from_le_bytes(get_bytes_8(&bytes[0x48..])?),
            mft_zone_start: i64::from_le_bytes(get_bytes_8(&bytes[0x50..])?),
            mft_zone_end: i64::from_le_bytes(get_bytes_8(&bytes[0x58..])?),
            ntfs_extended_volume_information: if extended {
                Some(NtfsExtendedVolumeData {
                    byte_count: u32::from_le_bytes(get_bytes_4(&bytes[0x60..])?),
                    major_version: u16::from_le_bytes(get_bytes_2(&bytes[0x64..])?),
                    minor_version: u16::from_le_bytes(get_bytes_2(&bytes[0x66..])?),
                    bytes_per_physical_sector: u32::from_le_bytes(get_bytes_4(&bytes[0x68..])?),
                    lfs_major_version: u16::from_le_bytes(get_bytes_2(&bytes[0x6c..])?),
                    lfs_minor_version: u16::from_le_bytes(get_bytes_2(&bytes[0x6e..])?),
                    max_device_trim_extent_count: u32::from_le_bytes(get_bytes_4(&bytes[0x70..])?),
                    max_device_trim_byte_count: u32::from_le_bytes(get_bytes_4(&bytes[0x74..])?),
                    max_volume_trim_extent_count: u32::from_le_bytes(get_bytes_4(&bytes[0x78..])?),
                    max_volume_trim_byte_count: u32::from_le_bytes(get_bytes_4(&bytes[0x7c..])?),
                })
            } else {
                None
            },
        })
    }
}
/// see [MS documentation](https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_extended_volume_data) for details.
#[derive(Debug, Clone)]
pub struct NtfsExtendedVolumeData {
    pub byte_count: u32,                   // 0x60
    pub major_version: u16,                // 0x64
    pub minor_version: u16,                // 0x66
    pub bytes_per_physical_sector: u32,    // 0x68
    pub lfs_major_version: u16,            // 0x6c
    pub lfs_minor_version: u16,            // 0x6e
    pub max_device_trim_extent_count: u32, // 0x70
    pub max_device_trim_byte_count: u32,   // 0x74
    pub max_volume_trim_extent_count: u32, // 0x78
    pub max_volume_trim_byte_count: u32,   // 0x7c
}

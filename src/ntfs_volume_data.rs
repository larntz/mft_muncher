pub struct NtfsVolumeData {
    pub volume_serial_number: i64,
    pub number_sectors: i64,
    pub total_clusters: i64,
    pub free_clusters: i64,
    pub total_reserved: i64,
    pub bytes_per_sector: u32,
    pub bytes_per_cluster: u32,
    pub bytes_per_file_record_segment: u32,
    pub clusters_per_file_record_segment: u32,
    pub mft_valid_data_length: i64,
    pub mft_start_lcn: i64,
    pub mft2_start_lcn: i64,
    pub mft_zone_start: i64,
    pub mft_zone_end: i64,
    pub ntfs_extended_volume_information: Option<NtfsExtendedVolumeData>,
}
impl NtfsVolumeData {
    pub fn new(bytes: &[u8], extended: bool) -> Result<NtfsVolumeData, std::io::Error> {
        unimplemented!()
    }
}

pub struct NtfsExtendedVolumeData {
    pub byte_count: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub bytes_per_physical_sector: u32,
    pub lfs_major_version: u16,
    pub lfs_minor_version: u16,
    pub max_device_trim_extent_count: u32,
    pub max_device_trim_byte_count: u32,
    pub max_volume_trim_extent_count: u32,
    pub max_volume_trim_byte_count: u32,
}

use crate::ntfs_utils::*;
use winapi::um::winnt::HANDLE;

/**
reference: [$INDEX_ALLOCATION](https://flatcap.org/linux-ntfs/ntfs/attributes/index_allocation.html)
**/

pub struct NtfsAttributeIndexAllocation {}

impl NtfsAttributeIndexAllocation {
    pub fn new_non_resident(bytes: &[u8], vcn_count: u8, data_length: u64, volume_handle: HANDLE) {
        //let x = load_data_runs(&bytes, vcn_count, data_length, volume_handle).unwrap();
        // let _ = std::process::Command::new("cmd.exe")
        //     .arg("/c")
        //     .arg("pause")
        //     .status();
    }
}

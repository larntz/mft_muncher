/// This module contains struct FileRecord. FileRecord corresponds to an NTFS File Record with all attributes.
pub mod file_record;

/// This module contains ntfs file attribute related structs.
pub mod ntfs_attributes;

/// This module contains ntfs volume information.
pub mod ntfs_volume_data;

/// This module enumerates all files on a volume via DeviceIoControl() win32 calls.
pub mod mft;

/// this module contains the ntfs USN_RECORD data structure definition.
mod usn_record;

/// This module contains utility functions used through this library.
mod utils;

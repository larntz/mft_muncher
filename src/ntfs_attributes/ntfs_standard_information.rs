use crate::utils::*;

/**
reference: [https://flatcap.org/linux-ntfs/ntfs/attributes/standard_information.html](https://flatcap.org/linux-ntfs/ntfs/attributes/standard_information.html)

_NOTE:_ this attribute is always resident.

```
Offset 	Size 	OS 	Description
~ 	    ~ 	  	    Standard Attribute Header
0x00 	8 	  	    C Time - File Creation
0x08 	8 	  	    A Time - File Altered
0x10 	8 	  	    M Time - MFT Changed
0x18 	8 	  	    R Time - File Read
0x20 	4 	  	    DOS File Permissions
0x24 	4 	  	    Maximum Number of Versions
0x28 	4 	  	    Version Number
0x2C 	4 	  	    Class Id
0x30 	4 	2K 	    Owner Id
0x34 	4 	2K 	    Security Id
0x38 	8 	2K 	    Quota Charged
0x40 	8 	2K 	    Update Sequence Number (USN)
```

dos attributes

```
Flag 	Description
0x0001 	Read-Only
0x0002 	Hidden
0x0004 	System
0x0020 	Archive
0x0040 	Device
0x0080 	Normal
0x0100 	Temporary
0x0200 	Sparse File
0x0400 	Reparse Point
0x0800 	Compressed
0x1000 	Offline
0x2000 	Not Content Indexed
0x4000 	Encrypted
```

**/
#[derive(Debug)]
#[repr(C)]
pub struct NtfsStandardInformationAttribute {
    pub file_creation: u64,  // 0x00
    pub file_altered: u64,   // 0x08
    pub mft_altered: u64,    // 0x10
    pub file_read: u64,      // 0x18
    pub dos_attributes: u32, // 0x20
    pub max_versions: u32,   //0x24
    pub version: u32,        // 0x28
    pub class_id: u32,       // 0x2c
    pub owner_id: u32,       // 0x30
    pub security_id: u32,    // 0x34
    pub quota_charged: u64,  // 0x38
    pub usn: u64,            // 0x40
}

impl NtfsStandardInformationAttribute {
    pub fn new(bytes: &[u8]) -> Result<NtfsStandardInformationAttribute, std::io::Error> {
        let file_creation = u64::from_le_bytes(get_bytes_8(&bytes[0x00..])?);
        let file_altered = u64::from_le_bytes(get_bytes_8(&bytes[0x08..])?);
        let mft_altered = u64::from_le_bytes(get_bytes_8(&bytes[0x10..])?);
        let file_read = u64::from_le_bytes(get_bytes_8(&bytes[0x18..])?);
        let dos_attributes = u32::from_le_bytes(get_bytes_4(&bytes[0x20..])?);
        let max_versions = u32::from_le_bytes(get_bytes_4(&bytes[0x24..])?);
        let version = u32::from_le_bytes(get_bytes_4(&bytes[0x28..])?);
        let class_id = u32::from_le_bytes(get_bytes_4(&bytes[0x2c..])?);
        let owner_id = u32::from_le_bytes(get_bytes_4(&bytes[0x30..])?);
        let security_id = u32::from_le_bytes(get_bytes_4(&bytes[0x34..])?);
        let quota_charged = u64::from_le_bytes(get_bytes_8(&bytes[0x38..])?);
        let usn = u64::from_le_bytes(get_bytes_8(&bytes[0x40..])?);

        Ok(NtfsStandardInformationAttribute {
            file_creation,
            file_altered,
            mft_altered,
            file_read,
            dos_attributes,
            max_versions,
            version,
            class_id,
            owner_id,
            security_id,
            quota_charged,
            usn,
        })
    }
}

// pub const NTFS_STANDARD_INFORMATION_ATTRIBUTE_LENGTH: usize =
//  std::mem::size_of::<NtfsStandardInformationAttribute>();

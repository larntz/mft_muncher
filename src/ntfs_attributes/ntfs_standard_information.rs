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
    pub file_creation: u64,
    pub file_altered: u64,
    pub mft_altered: u64,
    pub file_read: u64,
    pub dos_attributes: u32,
    pub max_versions: u32,
    pub version: u32,
    pub class_id: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub quota_charged: u64,
    pub usn: u64,
}

pub const NTFS_STANDARD_INFORMATION_ATTRIBUTE_LENGTH: usize =
    std::mem::size_of::<NtfsStandardInformationAttribute>();

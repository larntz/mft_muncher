/**
reference [https://flatcap.org/linux-ntfs/ntfs/attributes/file_name.html](https://flatcap.org/linux-ntfs/ntfs/attributes/file_name.html)

_NOTE:_ this attribute is always resident.

> As defined in $AttrDef, this attribute has a minimum size of 68 bytes and a maximum of 578 bytes. This equates to a maximum filename length of 255 Unicode characters.

```
Offset 	Size 	Description
~ 	    ~ 	    Standard Attribute Header
0x00 	8 	    File reference to the parent directory.
0x08 	8 	    C Time - File Creation
0x10 	8 	    A Time - File Altered
0x18 	8 	    M Time - MFT Changed
0x20 	8 	    R Time - File Read
0x28 	8 	    Allocated size of the file
0x30 	8 	    Real size of the file
0x38 	4 	    Flags, e.g. Directory, compressed, hidden
0x3c 	4 	    Used by EAs and Reparse
0x40 	1 	    Filename length in characters (L)
0x41 	1 	    Filename namespace
0x42 	2L 	    File name in Unicode (not null terminated)
```

flags:
```
Flag 	    Description
0x0001 	    Read-Only
0x0002 	    Hidden
0x0004 	    System
0x0020 	    Archive
0x0040 	    Device
0x0080 	    Normal
0x0100 	    Temporary
0x0200 	    Sparse File
0x0400 	    Reparse Point
0x0800 	    Compressed
0x1000 	    Offline
0x2000 	    Not Content Indexed
0x4000 	    Encrypted
0x10000000 	Directory (copy from corresponding bit in MFT record)
0x20000000 	Index View (copy from corresponding bit in MFT record)
```

**/

#[derive(Debug)]
#[repr(C)]
pub struct NtfsFileNameAttribute {
    pub parent_frn: u64,
    file_create: u64,
    file_modified: u64,
    mft_modified: u64,
    file_read: u64,
    allocated_size: u64,
    real_size: u64,
    flags: u32,
    ea_reparse: u32,
    pub filename_length: u8,
    pub filename_namespace: u8,
    pub filename: String,
}

impl NtfsFileNameAttribute {
    pub fn new(bytes: &[u8], length: u32) {
        dbg!(bytes);
    }
}

// pub const NTFS_FILE_NAME_ATTRIBUTE_LENGTH: usize = std::mem::size_of::<NtfsFileNameAttribute>();

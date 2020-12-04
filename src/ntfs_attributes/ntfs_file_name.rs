use crate::utils::*;

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
pub struct NtfsFileNameAttribute {
    pub parent_frn: u64,        // offset 0x00
    pub file_create: u64,       // offset 0x08
    pub file_modified: u64,     // offset 0x10
    pub mft_modified: u64,      // offset 0x18
    pub file_read: u64,         // offset 0x20
    pub allocated_size: u64,    // offset 0x28
    pub real_size: u64,         // offset 0x30
    pub flags: u32,             // offset 0x38
    pub ea_reparse: u32,        // offset 0x3c
    pub filename_length: u8,    // offset 0x40
    pub filename_namespace: u8, // offset 0x41
    pub filename: String,       // offset 0x42
}
impl NtfsFileNameAttribute {
    pub fn new(bytes: &[u8]) -> Result<NtfsFileNameAttribute, std::io::Error> {
        let parent_frn = u64::from_le_bytes(get_bytes_8(&bytes[0x00..])?);
        let file_create = u64::from_le_bytes(get_bytes_8(&bytes[0x08..])?);
        let file_modified = u64::from_le_bytes(get_bytes_8(&bytes[0x10..])?);
        let mft_modified = u64::from_le_bytes(get_bytes_8(&bytes[0x18..])?);
        let file_read = u64::from_le_bytes(get_bytes_8(&bytes[0x20..])?);
        let allocated_size = u64::from_le_bytes(get_bytes_8(&bytes[0x28..])?);
        let real_size = u64::from_le_bytes(get_bytes_8(&bytes[0x30..])?);
        let flags = u32::from_le_bytes(get_bytes_4(&bytes[0x38..])?);
        let ea_reparse = u32::from_le_bytes(get_bytes_4(&bytes[0x3c..])?);
        let filename_length = u8::from_le_bytes(get_bytes_1(&bytes[0x40..])?);
        let filename_namespace = u8::from_le_bytes(get_bytes_1(&bytes[0x41..])?);

        let filename_u16: Vec<u16> = bytes[0x42..0x42 + (2 * filename_length) as usize]
            .chunks_exact(2)
            .map(|x| u16::from_le_bytes(get_bytes_2(&x).expect("filename_u16 error")))
            .collect();
        let filename = String::from_utf16_lossy(&filename_u16);

        Ok(NtfsFileNameAttribute {
            parent_frn,
            file_create,
            file_modified,
            mft_modified,
            file_read,
            allocated_size,
            real_size,
            flags,
            ea_reparse,
            filename_length,
            filename_namespace,
            filename,
        })
    }
}

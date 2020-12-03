use crate::mft::MFT;
use std::convert::TryInto;

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
    pub parent_frn: u64,
    pub file_create: u64,
    pub file_modified: u64,
    pub mft_modified: u64,
    pub file_read: u64,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub ea_reparse: u32,
    pub filename_length: u8,
    pub filename_namespace: u8,
    pub filename: String,
}
const NTFS_FILE_NAME_ATTRIBUTE: usize = std::mem::size_of::<NtfsFileNameAttribute>();
impl NtfsFileNameAttribute {
    pub fn new(bytes: &[u8]) -> Result<NtfsFileNameAttribute, std::io::Error> {
        const PARENT_FRN_OFFSET: usize = 0x00;
        const CREATE_OFFSET: usize = 0x08;
        const MODIFIED_OFFSET: usize = 0x10;
        const MFT_MODIFIED_OFFSET: usize = 0x18;
        const READ_OFFSET: usize = 0x20;
        const ALLOCATED_OFFSET: usize = 0x28;
        const REAL_OFFSET: usize = 0x30;
        const FLAGS_OFFSET: usize = 0x38;
        const EA_REPARSE_OFFSET: usize = 0x3c;
        const FILENAME_LENGTH_OFFSET: usize = 0x40;
        const FILENAME_NAMESPACE_OFFSET: usize = 0x41;
        const FILENAME_OFFSET: usize = 0x42;

        if bytes.len() < FILENAME_OFFSET {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "we got 99 problems and this slice is one",
            ));
        }

        let size = CREATE_OFFSET - PARENT_FRN_OFFSET;
        let parent_frn = u64::from_le_bytes(
            bytes[PARENT_FRN_OFFSET..PARENT_FRN_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = MODIFIED_OFFSET - CREATE_OFFSET;
        let file_create = u64::from_le_bytes(
            bytes[CREATE_OFFSET..CREATE_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = MFT_MODIFIED_OFFSET - MODIFIED_OFFSET;
        let file_modified = u64::from_le_bytes(
            bytes[MODIFIED_OFFSET..MODIFIED_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = READ_OFFSET - MFT_MODIFIED_OFFSET;
        let mft_modified = u64::from_le_bytes(
            bytes[MFT_MODIFIED_OFFSET..MFT_MODIFIED_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = ALLOCATED_OFFSET - READ_OFFSET;
        let file_read = u64::from_le_bytes(
            bytes[READ_OFFSET..READ_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = REAL_OFFSET - ALLOCATED_OFFSET;
        let allocated_size = u64::from_le_bytes(
            bytes[ALLOCATED_OFFSET..ALLOCATED_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = FLAGS_OFFSET - REAL_OFFSET;
        let real_size = u64::from_le_bytes(
            bytes[REAL_OFFSET..REAL_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = EA_REPARSE_OFFSET - FLAGS_OFFSET;
        let flags = u32::from_le_bytes(
            bytes[FLAGS_OFFSET..FLAGS_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = FILENAME_LENGTH_OFFSET - EA_REPARSE_OFFSET;
        let ea_reparse = u32::from_le_bytes(
            bytes[EA_REPARSE_OFFSET..EA_REPARSE_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = FILENAME_NAMESPACE_OFFSET - FILENAME_LENGTH_OFFSET;
        let filename_length = u8::from_le_bytes(
            bytes[FILENAME_LENGTH_OFFSET..FILENAME_LENGTH_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );
        let size = FILENAME_OFFSET - FILENAME_NAMESPACE_OFFSET;
        let filename_namespace = u8::from_le_bytes(
            bytes[FILENAME_NAMESPACE_OFFSET..FILENAME_NAMESPACE_OFFSET + size]
                .try_into()
                .expect("promise me you'll never die"),
        );

        let filename_u16: Vec<u16> = bytes
            [FILENAME_OFFSET..FILENAME_OFFSET + (2 * filename_length) as usize]
            .chunks_exact(2)
            .map(|x| {
                u16::from_le_bytes(
                    x.try_into()
                        .expect("This is cool. Uh huh huh... Ow. Cut it out, butt-hole."),
                )
            })
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

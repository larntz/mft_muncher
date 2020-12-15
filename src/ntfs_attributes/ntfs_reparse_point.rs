use crate::ntfs_attributes::ATTRIBUTE_END;
use crate::ntfs_utils::*;
use crate::utils::*;

use winapi::um::winnt::HANDLE;

/**
reference: [https://flatcap.org/linux-ntfs/ntfs/attributes/reparse_point.html](https://flatcap.org/linux-ntfs/ntfs/attributes/reparse_point.html)

```text
Overview

As defined in $AttrDef, this attribute has a no minimum size but a maximum of 16384 bytes.

Layout of the Attribute (Microsoft Reparse Point)
Offset 	Size 	Description
~ 	~ 	Standard Attribute Header
0x00 	4 	Reparse Type (and Flags)
0x04 	2 	Reparse Data Length
0x06 	2 	Padding (align to 8 bytes)
0x08 	V 	Reparse Data (a)

Layout of the Attribute (Third-Party Reparse Point)
Offset 	Size 	Description
~ 	~ 	Standard Attribute Header
0x00 	4 	Reparse Type (and Flags)
0x04 	2 	Reparse Data Length
0x06 	2 	Padding (align to 8 bytes)
0x08 	16 	Reparse GUID
0x18 	V 	Reparse Data (a)

(a) The structure of the Reparse Data depends on the Reparse Type. There are
    three defined Reparse Data (SymLinks, VolLinks and RSS) + the Generic Reparse.

Symbolic Link Reparse Data
Offset 	Size 	Description
0x00 	2 	Substitute Name Offset
0x02 	2 	Substitute Name Length
0x04 	2 	Print Name Offset
0x08 	2 	Print Name Length
0x10 	V 	Path Buffer

Volume Link Reparse Data
Offset 	Size 	Description
0x00 	2 	Substitute Name Offset
0x02 	2 	Substitute Name Length
0x04 	2 	Print Name Offset
0x08 	2 	Print Name Length
0x10 	V 	Path Buffer
Reparse Tag Flags

These are just the predefined reparse flags

Flag 	Description
0x20000000 	Is alias
0x40000000 	Is high latency
0x80000000 	Is Microsoft
0x68000005 	NSS
0x68000006 	NSS recover
0x68000007 	SIS
0x68000008 	DFS
0x88000003 	Mount point
0xA8000004 	HSM
0xE8000000 	Symbolic link
```

**/

#[derive(Debug)]
pub struct NtfsReparsePointAttribute {
    pub reparse_type: u32,
    pub reparse_data_length: u16,
    pub reparse_guid: Option<Vec<u8>>,
}

impl NtfsReparsePointAttribute {
    pub fn new_resident(bytes: &[u8]) -> Result<NtfsReparsePointAttribute, std::io::Error> {
        let rpp = NtfsReparsePointAttribute {
            reparse_type: u32::from_le_bytes(get_bytes_4(&bytes[0x00..])?),
            reparse_data_length: u16::from_le_bytes(get_bytes_2(&bytes[0x04..])?),
            reparse_guid: None,
        };

        let t = u16::from_le_bytes(get_bytes_2(&bytes[0x00..])?);
        println!(
            "reparse type {:x} :: t {:x}, reparse data length {}",
            rpp.reparse_type, t, rpp.reparse_data_length
        );
        Ok(rpp)
    }
    pub fn new_non_resident(
        bytes: &[u8],
        vcn_count: u8,
        data_length: u64,
        volume_handle: HANDLE,
    ) -> Result<NtfsReparsePointAttribute, std::io::Error> {
        unimplemented!()
    }
}

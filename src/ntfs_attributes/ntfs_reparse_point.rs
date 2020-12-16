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

```

Note: Reparse points can be third part (e.g., Dropbox). I am only fully parsing well
defined MS reparse points.  Third party reparse points will be saved and documented, but
details are not available.

Third party's must tag their reparse points with a GUID.

> Reparse point GUIDs are assigned by the independent software vendor (ISV). An ISV MUST link one GUID to each assigned reparse point tag, and MUST always use that GUID with that tag.
[https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a4d08374-0e92-43e2-8f88-88b94112f070](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a4d08374-0e92-43e2-8f88-88b94112f070)

## Reparse Tags

Full list: [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4)

### IO_REPARSE_TAG_MOUNT_POINT

0xA0000003

Used for mount point support, specified in section [2.1.2.5](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ca069dad-ed16-42aa-b057-b6b207f447cc).

Examples of this are c:\users\bob\My Documents pointing to c:\users\bob\Documents

### IO_REPARSE_TAG_SYMLINK

0xA000000C

> Used for symbolic link support. See section [2.1.2.4](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b41f1cbf-10df-4a47-98d4-1c52a833d913).

### IO_REPARSE_TAG_APPEXECLINK

0x8000001B

> Used by Universal Windows Platform (UWP) packages to encode information that allows the application to be launched by CreateProcess. Server-side interpretation only, not meaningful over the wire.



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

        // todo process well known MS reparse types.
        if rpp.reparse_type & 0b10000000_00000000_00000000_00000000 == 0 {
            println!("non microsoft reparse");
            use std::convert::TryInto;
            let guid_bytes: [u8; 16] = bytes[0x08..0x18].try_into().expect("trying to make a guid");
            let guid = u128::from_le_bytes(guid_bytes);
            println!("guid: {:#x}", guid);
        } else {
            println!("microsoft reparse");
            println!("reparse type {:x}", rpp.reparse_type);
            println!("reparse length {}", rpp.reparse_data_length);

            match rpp.reparse_type {
                0xA000000C => {
                    let substitute_name_offset = u16::from_le_bytes(get_bytes_2(&bytes[0x08..])?);
                    let substitute_name_length = u16::from_le_bytes(get_bytes_2(&bytes[0x0a..])?);
                    println!(
                        "sub name offset {}, sub name length {}",
                        substitute_name_offset, substitute_name_length
                    );

                    // this name string can be null terminated
                    // this is the actual target file/directory the reparse point points to...
                    let mut _end = if substitute_name_length as usize <= bytes.len() {
                        substitute_name_length as usize
                    } else {
                        bytes.len()
                    };

                    let sub_name_u16: Vec<u16> = bytes[0x14 + substitute_name_offset as usize..]
                        .chunks_exact(2)
                        .map(|x| u16::from_le_bytes(get_bytes_2(&x).expect("filename_u16 error")))
                        .collect();
                    println!("sub_name_u16: {:?}", sub_name_u16);
                    let sub_name_u16: &[u16] = sub_name_u16
                        .split(|x| *x == 0 || *x == 65535)
                        .next()
                        .unwrap();
                    println!("sub_name_u16: {:?}", sub_name_u16);
                    let print_name_offset = u16::from_le_bytes(get_bytes_2(&bytes[0x0c..])?);
                    let print_name_length = u16::from_le_bytes(get_bytes_2(&bytes[0x0e..])?);
                    println!(
                        "print_name_offset {}, print name length {}",
                        print_name_offset, print_name_length,
                    );

                    // this name string can be null terminated
                    // this is the actual target file/directory the reparse point points to...
                    let print_name_u16: Vec<u16> = bytes[0x14 + print_name_offset as usize..]
                        .chunks_exact(2)
                        .map(|x| u16::from_le_bytes(get_bytes_2(&x).expect("filename_u16 error")))
                        .collect();
                    println!("print_name_u16: {:?}", print_name_u16);
                    let print_name_u16: &[u16] = print_name_u16.split(|x| *x == 0).next().unwrap();
                    println!("print_name_u16: {:?}", print_name_u16);
                    println!(
                        "subname: {}",
                        String::from_utf16(&sub_name_u16).expect("pens")
                    );
                    println!("subname: {}\n", String::from_utf16_lossy(&sub_name_u16));
                    println!("printname: {}\n", String::from_utf16_lossy(&print_name_u16));
                    println!(
                        "rpp data {:x?}\n\n\n",
                        &bytes[0x08..0x08 + rpp.reparse_data_length as usize]
                    );

                    // testing
                    // let _ = std::process::Command::new("cmd.exe")
                    //     .arg("/c")
                    //     .arg("pause")
                    //     .status();
                }
                _ => {}
            }
        }

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

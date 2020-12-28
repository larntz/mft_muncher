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

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xa0000003; // Used for mount point support, specified in section 2.1.2.5.
const IO_REPARSE_TAG_SYMLINK: u32 = 0xa000000c; // Used for symbolic link support.
const IO_REPARSE_TAG_APPEXECLINK: u32 = 0x8000001b; // Used by Universal Windows Platform (UWP) packages to encode information that allows the application to be launched by CreateProcess.
const IO_REPARSE_TAG_WCI: u32 = 0x80000018; // Used by the Windows Container Isolation filter.
const IO_REPARSE_TAG_AF_UNIX: u32 = 0x80000023; // Used by the Windows Subsystem for Linux (WSL) to represent a UNIX domain socket.

#[derive(Debug)]
pub struct NtfsReparsePointAttribute {
    pub reparse_type: NtfsReparseTagType,
    pub reparse_guid: Option<Vec<u8>>,
    pub substitute_name: Option<String>,
    pub print_name: Option<String>,
}

#[derive(Debug)]
pub enum NtfsReparseTagType {
    IoReparseTagMountPoint,
    IoReparseTagSymlink { relative_path: bool },
    IoReparseTagAppexeclink,
    IoReparseTagWci,
    IoReparseTagAfUnix,
    MicrosoftUnknown { tag_type: u32 },
    NonMsUnknown { tag_type: u32 },
}

impl NtfsReparsePointAttribute {
    pub fn new_resident(bytes: &[u8]) -> Result<NtfsReparsePointAttribute, std::io::Error> {
        let reparse_type_value = u32::from_le_bytes(get_bytes_4(&bytes)?);
        NtfsReparsePointAttribute::process_reparse_data(&bytes, reparse_type_value)
    }
    pub fn new_non_resident(
        bytes: &[u8],
        vcn_count: u8,
        data_length: u64,
        volume_handle: HANDLE,
    ) -> Result<NtfsReparsePointAttribute, std::io::Error> {
        let data = load_data_runs(&bytes, vcn_count, data_length, volume_handle)?;
        let reparse_type_value = u32::from_le_bytes(get_bytes_4(&data)?);
        NtfsReparsePointAttribute::process_reparse_data(&data, reparse_type_value)
    }

    fn process_reparse_data(
        bytes: &[u8],
        reparse_type_value: u32,
    ) -> Result<NtfsReparsePointAttribute, std::io::Error> {
        if NtfsReparsePointAttribute::is_ms_reparse(reparse_type_value) {
            match reparse_type_value {
                IO_REPARSE_TAG_MOUNT_POINT => {
                    // IO_REPARSE_TAG_MOUNT_POINT path buffer offset is 0x10,
                    let path_buffer_offset: usize = 0x10;
                    let sub_name_offset: usize = 0x08; // offset to the sub name offset
                    let print_name_offset: usize = 0x0c; // offset to the print name offset
                    let substitute_name: String = NtfsReparsePointAttribute::get_string(
                        &bytes,
                        sub_name_offset,
                        path_buffer_offset,
                    )?;
                    let print_name: String = NtfsReparsePointAttribute::get_string(
                        &bytes,
                        print_name_offset,
                        path_buffer_offset,
                    )?;

                    Ok(NtfsReparsePointAttribute {
                        reparse_type: NtfsReparseTagType::IoReparseTagMountPoint,
                        reparse_guid: None,
                        substitute_name: Some(substitute_name),
                        print_name: Some(print_name),
                    })
                }
                IO_REPARSE_TAG_SYMLINK => {
                    // but IO_REPARSE_TAG_SYMLINK has an extra 4 byte flag field
                    let flag_buffer_offset: usize = 0x10;
                    let path_buffer_offset: usize = 0x14;
                    let sub_name_offset: usize = 0x08; // offset to the sub name offset
                    let print_name_offset: usize = 0x0c; // offset to the print name offset
                    let substitute_name: String = NtfsReparsePointAttribute::get_string(
                        &bytes,
                        sub_name_offset,
                        path_buffer_offset,
                    )?;
                    let print_name: String = NtfsReparsePointAttribute::get_string(
                        &bytes,
                        print_name_offset,
                        path_buffer_offset,
                    )?;
                    let flags = u32::from_le_bytes(get_bytes_4(&bytes[flag_buffer_offset..])?);
                    Ok(NtfsReparsePointAttribute {
                        reparse_type: NtfsReparseTagType::IoReparseTagSymlink {
                            relative_path: if flags == 1 { true } else { false },
                        },
                        reparse_guid: None,
                        substitute_name: Some(substitute_name),
                        print_name: Some(print_name),
                    })
                }
                IO_REPARSE_TAG_APPEXECLINK => Ok(NtfsReparsePointAttribute {
                    reparse_type: NtfsReparseTagType::IoReparseTagAppexeclink,
                    reparse_guid: None,
                    substitute_name: None,
                    print_name: None,
                }),
                IO_REPARSE_TAG_WCI => Ok(NtfsReparsePointAttribute {
                    reparse_type: NtfsReparseTagType::IoReparseTagWci,
                    reparse_guid: None,
                    substitute_name: None,
                    print_name: None,
                }),
                IO_REPARSE_TAG_AF_UNIX => Ok(NtfsReparsePointAttribute {
                    reparse_type: NtfsReparseTagType::IoReparseTagAfUnix,
                    reparse_guid: None,
                    substitute_name: None,
                    print_name: None,
                }),
                _ => {
                    #[cfg(debug_assertions)]
                    {
                        println!("unknown MS reparse tag: {:#x}", reparse_type_value);
                        let _ = std::process::Command::new("cmd.exe")
                            .arg("/c")
                            .arg("pause")
                            .status();
                    }

                    Ok(NtfsReparsePointAttribute {
                        reparse_type: NtfsReparseTagType::MicrosoftUnknown {
                            tag_type: reparse_type_value,
                        },
                        reparse_guid: None,
                        substitute_name: None,
                        print_name: None,
                    })
                }
            }
        } else {
            use std::convert::TryInto;
            let guid_bytes: Vec<u8> = bytes[0x08..0x18].try_into().expect("trying to make a guid");
            Ok(NtfsReparsePointAttribute {
                reparse_type: NtfsReparseTagType::NonMsUnknown {
                    tag_type: reparse_type_value,
                },
                reparse_guid: Some(guid_bytes),
                substitute_name: None,
                print_name: None,
            })
        }
    }

    fn is_ms_reparse(reparse_type: u32) -> bool {
        // signifies this reparse point belongs to Microsoft
        reparse_type & 0b10000000_00000000_00000000_00000000 != 0
    }

    fn get_string(
        bytes: &[u8],
        offset: usize,
        path_offset: usize,
    ) -> Result<String, std::io::Error> {
        let name_offset = u16::from_le_bytes(get_bytes_2(&bytes[offset..])?) as usize + path_offset;
        let name_length = u16::from_le_bytes(get_bytes_2(&bytes[offset + 0x02..])?) as usize;
        let name_u16: Vec<u16> = bytes[name_offset..name_offset + name_length]
            .chunks_exact(2)
            .map(|x| u16::from_le_bytes(get_bytes_2(&x).unwrap_or([0, 0]))) // .expect("filename_u16 error")))
            .collect();

        Ok(String::from_utf16(&name_u16).unwrap_or("".to_string()))
    }
}

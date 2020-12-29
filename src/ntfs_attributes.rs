pub mod attribute_list;
pub mod data;
pub mod file_name;
pub mod index_root;
pub mod reparse_point;
pub mod standard_information;

use crate::ntfs_attributes::attribute_list::NtfsAttributeListAttribute;
use crate::utils::*;

use data::*;
use file_name::*;
use index_root::*;
use reparse_point::*;
use standard_information::*;

use winapi::um::winnt::HANDLE;

/**
reference: [https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header](https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header)

## Attribute Types

```text
Value 	Meaning

$STANDARD_INFORMATION
0x10
File attributes (such as read-only and archive), time stamps (such as file creation and last modified), and the hard link count.

$ATTRIBUTE_LIST
0x20
A list of attributes that make up the file and the file reference of the MFT file record in which each attribute is located.

$FILE_NAME
0x30
The name of the file, in Unicode characters.

$OBJECT_ID
0x40
An 64-byte object identifier assigned by the link-tracking service.

$VOLUME_NAME
0x60
The volume label. Present in the $Volume file.

$VOLUME_INFORMATION
0x70
The volume information. Present in the $Volume file.

$DATA
0x80
The contents of the file.

$INDEX_ROOT
0x90
Used to implement filename allocation for large directories.

$INDEX_ALLOCATION
0xA0
Used to implement filename allocation for large directories.

$BITMAP
0xB0
A bitmap index for a large directory.

$REPARSE_POINT
0xC0
The reparse point data.
```

```rust
typedef struct _ATTRIBUTE_RECORD_HEADER {
  ATTRIBUTE_TYPE_CODE TypeCode;
  ULONG               RecordLength;
  UCHAR               FormCode;
  UCHAR               NameLength;
  USHORT              NameOffset;
  USHORT              Flags;
  USHORT              Instance;
  union {
    struct {
      ULONG  ValueLength;
      USHORT ValueOffset;
      UCHAR  Reserved[2];
    } Resident;
    struct {
      VCN      LowestVcn;
      VCN      HighestVcn;
      USHORT   MappingPairsOffset;
      UCHAR    Reserved[6];
      LONGLONG AllocatedLength;
      LONGLONG FileSize;
      LONGLONG ValidDataLength;
      LONGLONG TotalAllocated;
    } Nonresident;
  } Form;
} ATTRIBUTE_RECORD_HEADER, *PATTRIBUTE_RECORD_HEADER;
```

reference: [https://flatcap.org/linux-ntfs/ntfs/concepts/attribute_header.html](https://flatcap.org/linux-ntfs/ntfs/concepts/attribute_header.html)

There are 4 combinations of attributes and headers:

1. resident, no name
1. resident, named
1. non-resident, no name
1. non-resident, named

**/

pub const ATTRIBUTE_TYPE_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTRIBUTE_TYPE_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTRIBUTE_TYPE_FILE_NAME: u32 = 0x30;
pub const ATTRIBUTE_TYPE_OBJECT_ID: u32 = 0x40;
pub const ATTRIBUTE_TYPE_SECURITY_DESCRIPTOR: u32 = 0x50;
pub const ATTRIBUTE_TYPE_VOLUME_NAME: u32 = 0x60;
pub const ATTRIBUTE_TYPE_VOLUME_INFORMATION: u32 = 0x70;
pub const ATTRIBUTE_TYPE_DATA: u32 = 0x80;
pub const ATTRIBUTE_TYPE_INDEX_ROOT: u32 = 0x90;
pub const ATTRIBUTE_TYPE_INDEX_ALLOCATION: u32 = 0xa0;
pub const ATTRIBUTE_TYPE_BITMAP: u32 = 0xb0;
pub const ATTRIBUTE_TYPE_REPARSE_POINT: u32 = 0xc0;
pub const ATTRIBUTE_TYPE_EA_INFORMATION: u32 = 0xd0;
pub const ATTRIBUTE_TYPE_EA: u32 = 0xe0;
pub const ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM: u32 = 0x100;
pub const ATTRIBUTE_END: u32 = 0xffffffff;

#[derive(Debug)]
// #[repr(C)]
pub struct NtfsAttributeHeader {
    pub attribute_type: u32,   // offset 0x00 The attribute type code.
    pub record_length: u32, // offset 0x04 The size of the attribute record, in bytes. This value reflects the required size for the record variant and is always rounded to the nearest quadword boundary.
    pub non_resident_flag: u8, // offset 0x08
    pub name_length: u8,    // offset 0x09
    pub name_offset: u16,   // offset 0x0a
    pub flags: u16,         // offset 0x0c
    pub attribute_id: u16,  // offset 0x0e
    pub union_data: NtfsAttributeUnion,
    pub attribute_name: Option<String>,
}

impl NtfsAttributeHeader {
    pub fn new(bytes: &[u8]) -> Result<NtfsAttributeHeader, std::io::Error> {
        let attribute_type = u32::from_le_bytes(get_bytes_4(&bytes[0x00..])?);
        let non_resident_flag = u8::from_le_bytes(get_bytes_1(&bytes[0x08..])?);
        let name_length = u8::from_le_bytes(get_bytes_1(&bytes[0x09..])?);
        let name_offset = u16::from_le_bytes(get_bytes_2(&bytes[0x0a..])?);

        Ok(NtfsAttributeHeader {
            attribute_type,
            record_length: u32::from_le_bytes(get_bytes_4(&bytes[0x04..])?),
            non_resident_flag,
            name_length,
            name_offset,
            flags: u16::from_le_bytes(get_bytes_2(&bytes[0x0c..])?),
            attribute_id: u16::from_le_bytes(get_bytes_2(&bytes[0x0e..])?),
            union_data: match non_resident_flag {
                0 => {
                    // resident
                    NtfsAttributeUnion::Resident(ResidentAttribute {
                        value_length: u32::from_le_bytes(get_bytes_4(&bytes[0x10..])?),
                        value_offset: u16::from_le_bytes(get_bytes_2(&bytes[0x14..])?),
                    })
                }
                _ => {
                    // non-resident
                    NtfsAttributeUnion::NonResident(NonResidentAttribute {
                        starting_vcn: u64::from_le_bytes(get_bytes_8(&bytes[0x10..])?),
                        highest_vcn: u64::from_le_bytes(get_bytes_8(&bytes[0x18..])?),
                        data_run_offset: u16::from_le_bytes(get_bytes_2(&bytes[0x20..])?),
                        allocated_length: i64::from_le_bytes(get_bytes_8(&bytes[0x28..])?),
                        file_size: i64::from_le_bytes(get_bytes_8(&bytes[0x30..])?),
                        valid_data_length: i64::from_le_bytes(get_bytes_8(&bytes[0x38..])?),
                        total_allocated: i64::from_le_bytes(get_bytes_8(&bytes[0x40..])?),
                    })
                }
            },
            attribute_name: if name_length == 0 || attribute_type == 0xffffffff {
                None
            } else {
                let filename_u16: Vec<u16> = bytes
                    [name_offset as usize..name_offset as usize + (2 * name_length) as usize]
                    .chunks_exact(2)
                    .map(|x| u16::from_le_bytes(get_bytes_2(&x).expect("filename_u16 error")))
                    .collect();
                Some(String::from_utf16_lossy(&filename_u16))
            },
        })
    }
}

#[derive(Debug)]
pub struct NtfsAttributeList {
    pub attributes: Vec<NtfsAttribute>,
}
impl NtfsAttributeList {
    pub fn new(bytes: &[u8], volume_handle: HANDLE) -> Result<Vec<NtfsAttribute>, std::io::Error> {
        let mut attributes: Vec<NtfsAttribute> = Vec::new();
        let mut offset: usize = 0;
        loop {
            match NtfsAttribute::new(&bytes[offset..], volume_handle)? {
                Some(attribute) => {
                    offset += attribute.header.record_length as usize;
                    attributes.push(attribute);
                }
                None => break, // or we loop forever
            }
        }
        Ok(attributes)
    }
}

#[derive(Debug)]
pub struct NtfsAttribute {
    pub header: NtfsAttributeHeader,
    pub metadata: NtfsAttributeType,
}
impl NtfsAttribute {
    pub fn new(
        bytes: &[u8],
        volume_handle: HANDLE,
    ) -> Result<Option<NtfsAttribute>, std::io::Error> {
        let header = NtfsAttributeHeader::new(bytes)?;
        match &header.attribute_type {
            &ATTRIBUTE_TYPE_STANDARD_INFORMATION => match &header.union_data {
                NtfsAttributeUnion::Resident(v) => {
                    let metadata = NtfsAttributeType::StandardInformation(
                        NtfsStandardInformationAttribute::new(&bytes[v.value_offset as usize..])?,
                    );
                    Ok(Some(NtfsAttribute { header, metadata }))
                }
                NtfsAttributeUnion::NonResident(_) => {
                    Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
                }
            },
            &ATTRIBUTE_TYPE_ATTRIBUTE_LIST => match &header.union_data {
                // todo: process each attribute in these lists
                NtfsAttributeUnion::Resident(v) => {
                    let length: usize = v.value_length as usize;
                    let metadata =
                        NtfsAttributeType::AttributeList(NtfsAttributeListAttribute::new_resident(
                            &bytes[v.value_offset as usize..v.value_offset as usize + length],
                        )?);

                    Ok(Some(NtfsAttribute { header, metadata }))
                }
                NtfsAttributeUnion::NonResident(v) => {
                    let length: usize = header.record_length as usize - v.data_run_offset as usize;
                    let metadata = NtfsAttributeType::AttributeList(
                        NtfsAttributeListAttribute::new_non_resident(
                            &bytes[v.data_run_offset as usize..v.data_run_offset as usize + length],
                            (v.highest_vcn - v.starting_vcn + 1) as u8,
                            v.valid_data_length as u64,
                            volume_handle,
                        )?,
                    );

                    Ok(Some(NtfsAttribute { header, metadata }))
                }
            },
            &ATTRIBUTE_TYPE_FILE_NAME => match &header.union_data {
                NtfsAttributeUnion::Resident(v) => {
                    let metadata = NtfsAttributeType::FileName(NtfsFileNameAttribute::new(
                        &bytes[v.value_offset as usize..],
                    )?);
                    Ok(Some(NtfsAttribute { header, metadata }))
                }
                NtfsAttributeUnion::NonResident(_) => {
                    Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
                }
            },
            &ATTRIBUTE_TYPE_OBJECT_ID => {
                #[cfg(debug_assertions)]
                unimplemented!();

                Ok(Some(NtfsAttribute {
                    header,
                    metadata: NtfsAttributeType::ObjectID,
                }))
            }
            &ATTRIBUTE_TYPE_DATA => match &header.union_data {
                NtfsAttributeUnion::Resident(v) => {
                    let metadata = NtfsAttributeType::Data(NtfsDataAttribute::new(
                        &bytes[v.value_offset as usize..],
                    )?);
                    Ok(Some(NtfsAttribute { header, metadata }))
                }
                NtfsAttributeUnion::NonResident(v) => {
                    let metadata = NtfsAttributeType::Data(NtfsDataAttribute::new(
                        &bytes[v.data_run_offset as usize..],
                    )?);
                    Ok(Some(NtfsAttribute { header, metadata }))
                }
            },
            &ATTRIBUTE_TYPE_INDEX_ROOT => match &header.union_data {
                // always resident
                NtfsAttributeUnion::Resident(v) => {
                    NtfsAttributeIndexRoot::new(&bytes[v.value_offset as usize..]);

                    Ok(Some(NtfsAttribute {
                        header,
                        metadata: NtfsAttributeType::IndexRoot,
                    }))
                }
                _ => {
                    panic!("$INDEX_ROOT should always be a resident attribute!");
                }
            },
            &ATTRIBUTE_TYPE_INDEX_ALLOCATION => {
                #[cfg(debug_assertions)]
                unimplemented!();

                Ok(Some(NtfsAttribute {
                    header,
                    metadata: NtfsAttributeType::IndexAllocation,
                }))
            }
            &ATTRIBUTE_TYPE_BITMAP => {
                #[cfg(debug_assertions)]
                unimplemented!();

                Ok(Some(NtfsAttribute {
                    header,
                    metadata: NtfsAttributeType::Bitmap,
                }))
            }
            &ATTRIBUTE_TYPE_REPARSE_POINT => match &header.union_data {
                NtfsAttributeUnion::Resident(v) => {
                    let metadata = NtfsAttributeType::ReparsePoint(
                        NtfsReparsePointAttribute::new_resident(&bytes[v.value_offset as usize..])?,
                    );
                    Ok(Some(NtfsAttribute { header, metadata }))
                }
                NtfsAttributeUnion::NonResident(v) => {
                    let length: usize = header.record_length as usize - v.data_run_offset as usize;
                    let metadata = NtfsAttributeType::ReparsePoint(
                        NtfsReparsePointAttribute::new_non_resident(
                            &bytes[v.data_run_offset as usize..v.data_run_offset as usize + length],
                            (v.highest_vcn - v.starting_vcn + 1) as u8,
                            v.valid_data_length as u64,
                            volume_handle,
                        )?,
                    );
                    Ok(Some(NtfsAttribute { header, metadata }))
                }
            },
            &ATTRIBUTE_TYPE_EA_INFORMATION => {
                #[cfg(debug_assertions)]
                unimplemented!();

                Ok(Some(NtfsAttribute {
                    header,
                    metadata: NtfsAttributeType::EaInformation,
                }))
            }
            &ATTRIBUTE_TYPE_EA => {
                #[cfg(debug_assertions)]
                unimplemented!();

                Ok(Some(NtfsAttribute {
                    header,
                    metadata: NtfsAttributeType::Ea,
                }))
            }
            &ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM => {
                #[cfg(debug_assertions)]
                unimplemented!();

                Ok(Some(NtfsAttribute {
                    header,
                    metadata: NtfsAttributeType::LoggedUtilityStream,
                }))
            }
            &ATTRIBUTE_END => Ok(None),
            _ => {
                eprintln!(
                    "+-+-+-+ unprocessed attribute type {:#x} +-+-+-+ \n{:#?}",
                    &header.attribute_type, &header
                );
                #[cfg(debug_assertions)]
                panic!("unknown attribute");

                Ok(None)
            }
        }
    }
}

#[derive(Debug)]
pub enum NtfsAttributeType {
    StandardInformation(NtfsStandardInformationAttribute),
    AttributeList(Vec<NtfsAttributeListAttribute>),
    FileName(NtfsFileNameAttribute),
    Data(NtfsDataAttribute),
    ObjectID, // we ignore for now: https://flatcap.org/linux-ntfs/ntfs/attributes/object_id.html
    IndexRoot, // we ignore for now: https://flatcap.org/linux-ntfs/ntfs/attributes/index_root.html
    IndexAllocation, // we ignore for now: https://flatcap.org/linux-ntfs/ntfs/attributes/index_allocation.html
    Bitmap, // we ignore for now: https://flatcap.org/linux-ntfs/ntfs/attributes/bitmap.html
    ReparsePoint(NtfsReparsePointAttribute),
    EaInformation,
    Ea,
    LoggedUtilityStream, // we ignore for now: https://flatcap.org/linux-ntfs/ntfs/attributes/logged_utility_stream.html
}
impl NtfsAttributeType {
    pub fn is_attribute_list(&self) -> bool {
        match self {
            NtfsAttributeType::AttributeList(_) => true,
            _ => false,
        }
    }
    pub fn get_attribute_list(&self) -> Option<&Vec<NtfsAttributeListAttribute>> {
        match self {
            NtfsAttributeType::AttributeList(x) => Some(x),
            _ => None,
        }
    }
}
#[derive(Debug)]
pub enum NtfsAttributeUnion {
    Resident(ResidentAttribute),
    NonResident(NonResidentAttribute),
}

#[derive(Debug)]
pub struct ResidentAttribute {
    pub value_length: u32, // offset 0x10 The size of the attribute value, in bytes.
    pub value_offset: u16, // offset 0x14 The offset to the value from the start of the attribute record, in bytes.
}

#[derive(Debug)]
pub struct NonResidentAttribute {
    pub starting_vcn: u64, // 0x10 The lowest virtual cluster number (VCN) covered by this attribute record.
    pub highest_vcn: u64,  // 0x18 The highest VCN covered by this attribute record.
    pub data_run_offset: u16, // 0x20 The offset to the mapping pairs array from the start of the attribute record, in bytes. For more information, see Remarks.
    // 6 bytes here are reserved or padding
    pub allocated_length: i64,  // 0x28
    pub file_size: i64, // 0x30 The file size (highest byte that can be read plus 1), in bytes. This member is not valid if LowestVcn is nonzero.
    pub valid_data_length: i64, // 0x38 The valid data length (highest initialized byte plus 1), in bytes. This value is rounded to the nearest cluster boundary. This member is not valid if LowestVcn is nonzero.
    pub total_allocated: i64, // 0x40 The total allocated for the file (the sum of the allocated clusters).
}

pub mod ntfs_attribute_list;
pub mod ntfs_data;
pub mod ntfs_file_name;
pub mod ntfs_standard_information;

use crate::ntfs_attributes::ntfs_attribute_list::NtfsAttributeListAttribute;
use crate::utils::*;
use ntfs_data::*;
use ntfs_file_name::*;
use ntfs_standard_information::*;

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

// todo create one struct containing all attribute information (header, metadata).
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
    pub fn new(bytes: &[u8]) -> Result<Vec<NtfsAttribute>, std::io::Error> {
        let mut attributes: Vec<NtfsAttribute> = Vec::new();
        let mut offset: usize = 0;
        loop {
            match NtfsAttribute::new(&bytes[offset..])? {
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
    pub fn new(bytes: &[u8]) -> Result<Option<NtfsAttribute>, std::io::Error> {
        let header = NtfsAttributeHeader::new(bytes)?;
        match &header.attribute_type {
            0x10 => match &header.union_data {
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
            0x20 => match &header.union_data {
                // todo: process each attribute that is in this
                NtfsAttributeUnion::Resident(v) => {
                    let metadata =
                        NtfsAttributeType::AttributeList(NtfsAttributeListAttribute::new(
                            &bytes[v.value_offset as usize..],
                            v.value_length as usize,
                        )?);

                    Ok(Some(NtfsAttribute { header, metadata }))
                }
                NtfsAttributeUnion::NonResident(v) => {
                    // todo how parse NonResident attributes??
                    // dbg!(&header);
                    // let metadata =
                    //     NtfsAttributeType::AttributeList(vec![NtfsAttributeListAttribute {
                    //         attribute_type: 0,
                    //         record_length: 0,
                    //         name_length: 0,
                    //         name_offset: 0,
                    //         starting_vcn: 0,
                    //         base_frn: 0,
                    //         attribute_name: None,
                    //     }]);
                    let metadata =
                        NtfsAttributeType::AttributeList(NtfsAttributeListAttribute::new(
                            &bytes[0x0e as usize..],
                            v.valid_data_length as usize,
                        )?);
                    // dbg!(&metadata);
                    // panic!("just checking if this can be non-resident");
                    Ok(Some(NtfsAttribute { header, metadata }))
                }
            },
            0x30 => match &header.union_data {
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
            0x40 => Ok(Some(NtfsAttribute {
                header,
                metadata: NtfsAttributeType::ObjectID,
            })),
            0x80 => match &header.union_data {
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
            0x90 => Ok(Some(NtfsAttribute {
                header,
                metadata: NtfsAttributeType::IndexRoot,
            })),
            0xa0 => Ok(Some(NtfsAttribute {
                header,
                metadata: NtfsAttributeType::IndexAllocation,
            })),
            0xb0 => Ok(Some(NtfsAttribute {
                header,
                metadata: NtfsAttributeType::Bitmap,
            })),
            0xc0 => Ok(Some(NtfsAttribute {
                header,
                metadata: NtfsAttributeType::ReparsePoint,
            })),
            0xd0 => Ok(Some(NtfsAttribute {
                header,
                metadata: NtfsAttributeType::EaInformation,
            })),
            0xe0 => Ok(Some(NtfsAttribute {
                header,
                metadata: NtfsAttributeType::Ea,
            })),
            0x100 => Ok(Some(NtfsAttribute {
                header,
                metadata: NtfsAttributeType::LoggedUtilityStream,
            })),
            0xffffffff => Ok(None),
            _ => {
                eprintln!(
                    "+-+-+-+ unprocessed attribute type {:#x} +-+-+-+ \n{:#?}",
                    &header.attribute_type, &header
                );
                panic!("add me");
                // Ok(None)
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
    ReparsePoint, // todo https://flatcap.org/linux-ntfs/ntfs/attributes/reparse_point.html
    EaInformation,
    Ea,
    LoggedUtilityStream, // we ignore for now: https://flatcap.org/linux-ntfs/ntfs/attributes/logged_utility_stream.html
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

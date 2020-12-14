use crate::ntfs_attributes::*;
use crate::utils::*;

use crate::ntfs_attributes::ntfs_attribute_list::NtfsAttributeListAttribute;
use crate::ntfs_attributes::NtfsAttributeType;
use winapi::um::winnt::HANDLE;

#[derive(Debug, Clone, Default)]
pub struct FileRecord {
    pub file_name: String,
    pub frn: u64,
    pub parent_links: Vec<u64>,
    pub attributes: u32,
    pub allocated_size_bytes: u32,
    pub real_size_bytes: u32,
    pub created: u64,
    pub accessed: u64,
    pub written: u64,
}
/**
reference: [https://flatcap.org/linux-ntfs/ntfs/concepts/file_record.html](https://flatcap.org/linux-ntfs/ntfs/concepts/file_record.html)

```
Offset 	Size 	OS 	Description
0x00 	4 	  	Magic number 'FILE'
0x04 	2 	  	Offset to the Update Sequence
0x06 	2 	  	Size in words of Update Sequence (S)
0x08 	8 	  	$LogFile Sequence Number (LSN)
0x10 	2 	  	Sequence number
0x12 	2 	  	Hard link count
0x14 	2 	  	Offset to the first Attribute
0x16 	2 	  	Flags
0x18 	4 	  	Real size of the FILE record
0x1C 	4 	  	Allocated size of the FILE record
0x20 	8 	  	File reference to the base FILE record
0x28 	2 	  	Next Attribute Id
0x2A 	2 	XP 	Align to 4 byte boundary
0x2C 	4 	XP 	Number of this MFT Record
```

**/
#[derive(Debug)]
#[repr(C)]
pub struct NtfsFileRecordHeader {
    //todo create new() constructor for NtfsFileRecordHeader
    pub magic_number: u32,            // 0x00
    pub update_sequence_offset: u16,  // 0x04
    pub update_sequence_size: u16,    // 0x06  size in words not bytes!!
    pub logfile_sequence_number: u64, // 0x08
    pub sequence_number: u16,         // 0x10
    pub hard_link_count: u16,         // 0x12
    pub attribute_offset: u16,        // 0x14
    pub flags: u16,                   // 0x16 0x1 == record in use, 0x2 directory.. need to verify
    pub real_record_size: u32,        // 0x18
    pub allocated_record_size: u32,   // 0x1c
    pub base_frn: u64,                // 0x20
    pub next_attribute_id: u16,       // 0x28
    pub mft_record_number: u32,       // 0x2c
}

impl NtfsFileRecordHeader {
    pub fn new(bytes: &[u8]) -> Result<NtfsFileRecordHeader, std::io::Error> {
        Ok(NtfsFileRecordHeader {
            magic_number: u32::from_le_bytes(get_bytes_4(&bytes[0x00..])?),
            update_sequence_offset: u16::from_le_bytes(get_bytes_2(&bytes[0x04..])?),
            update_sequence_size: u16::from_le_bytes(get_bytes_2(&bytes[0x06..])?),
            logfile_sequence_number: u64::from_le_bytes(get_bytes_8(&bytes[0x08..])?),
            sequence_number: u16::from_le_bytes(get_bytes_2(&bytes[0x10..])?),
            hard_link_count: u16::from_le_bytes(get_bytes_2(&bytes[0x12..])?),
            attribute_offset: u16::from_le_bytes(get_bytes_2(&bytes[0x14..])?),
            flags: u16::from_le_bytes(get_bytes_2(&bytes[0x16..])?),
            real_record_size: u32::from_le_bytes(get_bytes_4(&bytes[0x18..])?),
            allocated_record_size: u32::from_le_bytes(get_bytes_4(&bytes[0x1c..])?),
            base_frn: u64::from_le_bytes(get_bytes_8(&bytes[0x20..])?),
            next_attribute_id: u16::from_le_bytes(get_bytes_2(&bytes[0x28..])?),
            mft_record_number: u32::from_le_bytes(get_bytes_4(&bytes[0x2c..])?),
        })
    }
}

#[derive(Debug)]
pub struct NtfsFileRecord {
    pub file_record_number: u64,
    pub header: NtfsFileRecordHeader,
    pub attributes: Vec<NtfsAttribute>,
}

impl NtfsFileRecord {
    pub fn new(
        file_record_number: u64,
        slice: &[u8],
        volume_handle: HANDLE,
    ) -> Result<NtfsFileRecord, std::io::Error> {
        let header = NtfsFileRecordHeader::new(&slice)?;
        let mut attributes =
            NtfsAttributeList::new(&slice[header.attribute_offset as usize..], volume_handle)?;

        let attribute_lists: Vec<&NtfsAttribute> = attributes
            .iter()
            .filter(|x| x.metadata.is_attribute_list())
            .collect();

        for list in attribute_lists {
            for item in list.metadata.get_attribute_list().unwrap() {
                // get file record for attributes in list where base_frn != frn.
            }
        }

        Ok(NtfsFileRecord {
            file_record_number,
            header,
            attributes,
        })
    }

    pub fn file_name(&self) -> Option<String> {
        for attribute in self
            .attributes
            .iter()
            .filter(|x| x.header.attribute_type == ATTRIBUTE_TYPE_FILE_NAME)
        {
            if let NtfsAttributeType::FileName(file_name) = &attribute.metadata {
                if file_name.filename_namespace == 1 || file_name.filename_namespace == 3 {
                    return Some(file_name.filename.clone());
                }
            }
        }
        None
    }
}

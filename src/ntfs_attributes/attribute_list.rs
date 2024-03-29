use crate::ntfs_attributes::ATTRIBUTE_END;
use crate::ntfs_utils::*;
use crate::utils::*;

use winapi::um::winnt::HANDLE;

/**
This struct brought to you by the Dept. of Redundancy Dept.

reference: [https://flatcap.org/linux-ntfs/ntfs/attributes/attribute_list.html](https://flatcap.org/linux-ntfs/ntfs/attributes/attribute_list.html)


Offset 	Size 	Description
~ 	    ~ 	    Standard Attribute Header
0x00 	4 	    Type
0x04 	2 	    Record length
0x06 	1 	    Name length (N)
0x07 	1 	    Offset to Name (a)
0x08 	8 	    Starting VCN (b)
0x10 	8 	    Base File Reference of the attribute
0x18 	2 	    Attribute Id (c)
0x1A 	2N 	    Name in Unicode (if N > 0)

**/
#[derive(Debug)]
pub struct NtfsAttributeListAttribute {
    pub attribute_type: u32,            // 0x00
    pub record_length: u16,             // 0x04
    pub name_length: u8,                // 0x06
    pub name_offset: u8,                // 0x07
    pub starting_vcn: u64,              // 0x10
    pub base_frn: u64,                  // 0x18
    pub attribute_name: Option<String>, // 0x1a
}

impl NtfsAttributeListAttribute {
    pub fn new_resident(bytes: &[u8]) -> Result<Vec<NtfsAttributeListAttribute>, std::io::Error> {
        let mut offset: usize = 0;
        let mut list: Vec<NtfsAttributeListAttribute> = Vec::new();

        while offset < bytes.len() {
            // this works ONLY if the ATTRIBUTE_LIST is resident.  Otherwise there is no offset and we loop forever or worse
            let attribute_type = u32::from_le_bytes(get_bytes_4(&bytes[offset + 0x00..])?);
            let record_length = u16::from_le_bytes(get_bytes_2(&bytes[offset + 0x04..])?);
            let name_length = u8::from_le_bytes(get_bytes_1(&bytes[offset + 0x06..])?);
            let name_offset = u8::from_le_bytes(get_bytes_1(&bytes[offset + 0x07..])?);
            let starting_vcn = u64::from_le_bytes(get_bytes_8(&bytes[offset + 0x08..])?);
            let base_frn = u64::from_le_bytes(get_bytes_8(&bytes[offset + 0x10..])?);
            let attribute_name = if name_length == 0 || attribute_type == ATTRIBUTE_END {
                None
            } else {
                let attribute_name_u16: Vec<u16> = bytes[offset + name_offset as usize
                    ..offset + name_offset as usize + (2 * name_length) as usize]
                    .chunks_exact(2)
                    .map(|x| u16::from_le_bytes(get_bytes_2(&x).expect("attribute_name_u16 error")))
                    .collect();
                Some(String::from_utf16_lossy(&attribute_name_u16))
            };

            list.push(NtfsAttributeListAttribute {
                attribute_type,
                record_length,
                name_length,
                name_offset,
                starting_vcn,
                base_frn,
                attribute_name,
            });

            if record_length == 0 {
                break;
            }
            offset += record_length as usize;
        }

        Ok(list)
    }

    pub fn new_non_resident(
        bytes: &[u8],
        vcn_count: u8,
        data_length: u64,
        volume_handle: HANDLE,
    ) -> Result<Vec<NtfsAttributeListAttribute>, std::io::Error> {
        let mut list: Vec<NtfsAttributeListAttribute> = Vec::new();
        let x = load_data_runs(&bytes, vcn_count, data_length, volume_handle)?;

        // loop to process data read from disk
        let mut offset: usize = 0;
        while offset < x.len() {
            let attribute_type = u32::from_le_bytes(get_bytes_4(&x[offset + 0x00..])?);
            let record_length = u16::from_le_bytes(get_bytes_2(&x[offset + 0x04..])?);
            let name_length = u8::from_le_bytes(get_bytes_1(&x[offset + 0x06..])?);
            let name_offset = u8::from_le_bytes(get_bytes_1(&x[offset + 0x07..])?);
            let starting_vcn = u64::from_le_bytes(get_bytes_8(&x[offset + 0x08..])?);
            let base_frn = u64::from_le_bytes(get_bytes_8(&x[offset + 0x10..])?);
            let attribute_name = if name_length == 0 {
                None
            } else {
                let attribute_name_u16: Vec<u16> = x[offset + name_offset as usize
                    ..offset + name_offset as usize + (2 * name_length) as usize]
                    .chunks_exact(2)
                    .map(|x| u16::from_le_bytes(get_bytes_2(&x).expect("attribute_name_u16 error")))
                    .collect();
                Some(String::from_utf16_lossy(&attribute_name_u16))
            };

            list.push(NtfsAttributeListAttribute {
                attribute_type,
                record_length,
                name_length,
                name_offset,
                starting_vcn,
                base_frn,
                attribute_name,
            });

            if record_length == 0 {
                break;
            }
            offset += record_length as usize;
        }
        Ok(list)
    }
}

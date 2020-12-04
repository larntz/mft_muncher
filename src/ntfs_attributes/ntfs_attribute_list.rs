use crate::utils::*;

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
    pub fn new(bytes: &[u8]) -> Result<NtfsAttributeListAttribute, std::io::Error> {
        let attribute_type = u32::from_le_bytes(get_bytes_4(&bytes[0x00..])?);
        let name_length = u8::from_le_bytes(get_bytes_1(&bytes[0x06..])?);
        let name_offset = u8::from_le_bytes(get_bytes_1(&bytes[0x07..])?);

        Ok(NtfsAttributeListAttribute {
            attribute_type,
            record_length: u16::from_le_bytes(get_bytes_2(&bytes[0x04..])?),
            name_length,
            name_offset,
            starting_vcn: u64::from_le_bytes(get_bytes_8(&bytes[0x10..])?),
            base_frn: u64::from_le_bytes(get_bytes_8(&bytes[0x18..])?),
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

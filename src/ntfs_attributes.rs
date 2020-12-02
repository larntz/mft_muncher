pub mod ntfs_file_name;
pub mod ntfs_standard_information;

use ntfs_file_name::*;
use ntfs_standard_information::*;

/**
refrence: [https://flatcap.org/linux-ntfs/ntfs/concepts/attribute_header.html](https://flatcap.org/linux-ntfs/ntfs/concepts/attribute_header.html)

There are 4 combinations of attributes and headers:

1. resident, no name
1. resident, named
1. non-resident, no name
1. non-resident, named

```
Offset 	Size 	Value 	Description
0x00 	4 	  	        Attribute Type (e.g. 0x10, 0x60)
0x04 	4 	  	        Length (including this header)
0x08 	1 	    0x00 	Non-resident flag
0x09 	1 	    0x00 	Name length
0x0A 	2 	    0x00 	Offset to the Name
0x0C 	2 	    0x00 	Flags
0x0E 	2 	  	        Attribute Id (a)
0x10 	4 	    L 	    Length of the Attribute
0x14 	2 	    0x18 	Offset to the Attribute
```

This struct contains the fields common between resident attributes.
**/

// todo create headers for all 4 combinations or find a way to pack them into one.
#[derive(Debug)]
#[repr(C)]
pub struct NtfsResidentAttributeCommonHeader {
    pub attribute_type: u32,
    pub length_with_header: u32,
    pub non_resident_flag: u8,
    pub name_length: u8,
    pub name_offset: u16,
    pub flags: u16,
    pub attribute_id: u16,
    pub attribute_length: u32,
    pub attribute_offset: u16,
}
pub const NTFS_RESIDENT_ATTRIBUTE_COMMON_HEADER_LENGTH: usize =
    std::mem::size_of::<NtfsResidentAttributeCommonHeader>();

pub enum NtfsAttributeTypes {
    StandardInformation(NtfsStandardInformationAttribute),
}

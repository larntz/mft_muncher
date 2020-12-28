use crate::utils::*;

/**
References:

 - [$index_root](https://flatcap.org/linux-ntfs/ntfs/attributes/index_root.html)
 - [index node header](https://flatcap.org/linux-ntfs/ntfs/concepts/node_header.html)
 - [index entry](https://flatcap.org/linux-ntfs/ntfs/concepts/index_entry.html)

**/

#[derive(Debug)]
pub struct NtfsAttributeIndexRoot {
    attribute_type: u32,           // 0x00
    collation_rule: u32,           // 0x04
    bytes_per_index_record: u32,   // 0x08
    clusters_per_index_record: u8, // 0x0c
    // index node header values
    offset_to_first_entry: u32,    // 0x10
    total_size_index_entries: u32, // 0x14
    allocated_node_size: u32,      // 0x18
    leaf_flag: u8,                 // 0x19
}

#[derive(Debug)]
pub struct NtfsIndexEntry {
    file_reference: u64, // 0x00
    // index_entry_length: u16, // 0x08
    // stream_length: u16,      // 0x0a
    flags: u8,       // 0x0c, 1 == index points to sub node, 2 == last index entry in node
    stream: Vec<u8>, // 0x10, A copy of the body (without header) of the attribute
    vcn: u64,        // (index_entry_length - 8)
}

impl NtfsAttributeIndexRoot {
    // todo finish index root attribute processing
    pub fn new(bytes: &[u8]) {
        //-> Result<NtfsAttributeIndexRoot, std::io::Error> {
        let attribute_type: u32 = u32::from_le_bytes(get_bytes_4(&bytes).unwrap());
        println!("index root attribute type {:#x}", attribute_type);
        let collation_type: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x04..]).unwrap());
        println!("collation type {:#x}", collation_type);
        let bytes_per_index: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x08..]).unwrap());
        println!("bytes per index {}", bytes_per_index);
        let offset_to_first_entry: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x10..]).unwrap());
        println!("offset to first entry {}", offset_to_first_entry);
        let total_size_of_entries: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x14..]).unwrap());
        println!("total size of entries {}", total_size_of_entries);
        let allocated_node_size: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x18..]).unwrap());
        println!("allocated node size {}", allocated_node_size);
        let leaf_flag: u8 = u8::from_le_bytes(get_bytes_1(&bytes[0x19..]).unwrap());
        println!("leaf_flag {:#x}", leaf_flag);

        // unimplemented!()
    }
}

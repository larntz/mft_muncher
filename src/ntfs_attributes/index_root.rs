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
        println!("\n============ attribute ============");
        let attribute_type: u32 = u32::from_le_bytes(get_bytes_4(&bytes).unwrap());
        println!("index root attribute type {:#x}", attribute_type);
        let collation_type: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x04..]).unwrap());
        println!("collation type {:#x}", collation_type);
        let bytes_per_index: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x08..]).unwrap());
        println!("bytes per index {}", bytes_per_index);
        let clusters_per_index = u8::from_le_bytes(get_bytes_1(&bytes[0x12..]).unwrap());
        println!("clusters per index {}", clusters_per_index);

        // index node header items
        println!("\n= index node header =================");
        let offset_to_first_entry: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x10..]).unwrap());
        println!("offset tr first entry {}", offset_to_first_entry);
        let total_size_of_entries: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x14..]).unwrap());
        println!("total size of entries {}", total_size_of_entries);
        let allocated_node_size: u32 = u32::from_le_bytes(get_bytes_4(&bytes[0x18..]).unwrap());
        println!("allocated node size {}", allocated_node_size);
        let leaf_flag: u8 = u8::from_le_bytes(get_bytes_1(&bytes[0x19..]).unwrap());
        println!("leaf_flag {:#x}", leaf_flag);

        // index entries
        let mut entry_offset: usize = 0;
        let entries = &bytes[0x20..];
        println!("{:?}", &bytes[0x20..]);
        while entry_offset < total_size_of_entries as usize {
            println!("\n= entry loop ======================");
            println!("\nentry_offset {}\n", entry_offset);
            let entry = &entries[entry_offset..];
            println!("{:?}", &entry[0..]);
            let frn = u64::from_le_bytes(get_bytes_8(&entry[0..]).unwrap());
            println!("frn  {}", frn);
            let length_of_entry = u16::from_le_bytes(get_bytes_2(&entry[8..]).unwrap());
            println!("length of entry {}", length_of_entry);
            let length_of_stream = u16::from_le_bytes(get_bytes_2(&entry[10..]).unwrap());
            println!("length of stream {}", length_of_stream);
            let entry_flag: u8 = u8::from_le_bytes(get_bytes_1(&entry[12..]).unwrap());
            println!("entry_flag {:#x}\n", entry_flag);

            // if length_of_stream > 0
            //     && length_of_entry > 0
            //     && attribute_type == 0x30
            //     && (entry_flag == 0x1 || entry_flag == 0x0)
            if attribute_type == 0x30 && length_of_entry > 0 && entry_flag < 0x2 {
                println!("\t= stream ==========================");
                let stream_offset = entry_offset + 0x10;
                let stream = &entry[0x10..]; // stream_offset + length_of_stream as usize];
                println!("\tstream {:?}", &stream);
                let parent_dir_frn = u64::from_le_bytes(get_bytes_8(&stream).unwrap());
                println!("\tparent dir frn {}", parent_dir_frn);
                let filename_length = u8::from_le_bytes(get_bytes_1(&stream[0x40..]).unwrap());
                println!("\tfilename_length {}", filename_length);
                let file_namespace = u8::from_le_bytes(get_bytes_1(&stream[0x41..]).unwrap());
                println!("\tfile_namespace {}", file_namespace);
                if filename_length > 0 {
                    let filename: Vec<u16> = stream[0x42..0x42 + (2 * filename_length) as usize]
                        .chunks_exact(2)
                        .map(|x| {
                            u16::from_le_bytes(get_bytes_2(&x).expect("attribute_name_u16 error"))
                        })
                        .collect();
                    println!("\tfile name {}", String::from_utf16_lossy(&filename));
                }
            } else {
                break;
            }

            entry_offset += length_of_entry as usize;
        }
        // unimplemented!()
    }
}

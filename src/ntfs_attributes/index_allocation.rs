use crate::ntfs_utils::*;
use crate::utils::*;
use winapi::um::winnt::HANDLE;

/**
reference: [$INDEX_ALLOCATION](https://flatcap.org/linux-ntfs/ntfs/attributes/index_allocation.html)
**/

pub struct NtfsAttributeIndexAllocation {}

impl NtfsAttributeIndexAllocation {
    pub fn new_non_resident(bytes: &[u8], vcn_count: u8, data_length: u64, volume_handle: HANDLE) {
        let mut x = load_data_runs(&bytes, vcn_count, data_length, volume_handle).unwrap();
        let usn_offset = u16::from_le_bytes(get_bytes_2(&x[4..6]).unwrap());
        println!("usn_offset {:#x}", usn_offset);
        let usn_size = u16::from_le_bytes(get_bytes_2(&x[6..8]).unwrap());
        println!("usn_size = {}", usn_size);

        println!(
            "usn {:x?}",
            &x[usn_offset as usize..usn_offset as usize + 2]
        );
        println!(
            "usn array {:x?}",
            &x[0x2A..0x2A + (2 * usn_size) as usize - 2]
        );

        let first_entry_offset = u32::from_le_bytes(get_bytes_4(&x[0x18..]).unwrap());
        println!("first_entry_offset {}", first_entry_offset);
        let total_size_of_entries: u32 =
            u32::from_le_bytes(get_bytes_4(&x[0x18 + 0x04..]).unwrap());
        println!("total_size_of_entries {}", total_size_of_entries);
        let allocated_node_size: u32 = u32::from_le_bytes(get_bytes_4(&x[0x18 + 0x08..]).unwrap());
        println!("allocated node size {}", allocated_node_size);
        let leaf_flag: u8 = u8::from_le_bytes(get_bytes_1(&x[0x18 + 0x0c..]).unwrap());
        println!("leaf_flag {:#x}", leaf_flag);

        println!("x.len() {}", x.len());
        println!("x {:x?}", x);
        x.truncate((first_entry_offset + total_size_of_entries) as usize);
        println!("x truncated {:x?}", x);

        let _ = std::process::Command::new("cmd.exe")
            .arg("/c")
            .arg("pause")
            .status();

        // index entries
        let mut entry_offset: usize = first_entry_offset as usize;
        while entry_offset < total_size_of_entries as usize {
            println!("\n= entry loop ======================");
            println!("\nentry_offset {}\n", entry_offset);
            let entry = &x[entry_offset..];
            println!("{:?}", &entry);
            let frn = u64::from_le_bytes(get_bytes_8(&entry[0..]).unwrap());
            println!("frn  {}", frn);
            let length_of_entry = u16::from_le_bytes(get_bytes_2(&entry[8..]).unwrap());
            println!("length of entry {}", length_of_entry);
            let length_of_stream = u16::from_le_bytes(get_bytes_2(&entry[10..]).unwrap());
            println!("length of stream {}", length_of_stream);
            let entry_flag: u8 = u8::from_le_bytes(get_bytes_1(&entry[12..]).unwrap());
            println!("entry_flag {:#x}\n", entry_flag);

            if length_of_entry == 0 {
                break;
            }
            match entry_flag {
                0x3 | 0x1 => {
                    let sub_node_vcn = u64::from_le_bytes(
                        get_bytes_8(&entry[length_of_entry as usize - 8..]).unwrap(),
                    );
                    println!("sub node vcn {}", sub_node_vcn);
                    break;
                }
                0x00 => {
                    //if attribute_type == 0x30 {
                    println!("\t= stream ==========================");
                    let stream = &entry[0x10..]; // stream_offset + length_of_stream as usize];
                    println!("\tstream {:?}", &stream);
                    let parent_dir_frn = u64::from_le_bytes(get_bytes_8(&stream).unwrap());
                    println!("\tparent dir frn {}", parent_dir_frn);
                    let filename_length = u8::from_le_bytes(get_bytes_1(&stream[0x40..]).unwrap());
                    println!("\tfilename_length {}", filename_length);
                    let file_namespace = u8::from_le_bytes(get_bytes_1(&stream[0x41..]).unwrap());
                    println!("\tfile_namespace {}", file_namespace);
                    if filename_length > 0 {
                        let filename: Vec<u16> = stream
                            [0x42..0x42 + (2 * filename_length) as usize]
                            .chunks_exact(2)
                            .map(|x| {
                                u16::from_le_bytes(
                                    get_bytes_2(&x).expect("attribute_name_u16 error"),
                                )
                            })
                            .collect();
                        println!("\tfile name {}", String::from_utf16_lossy(&filename));
                    }
                    //}
                }
                _ => {
                    break;
                }
            }

            entry_offset += length_of_entry as usize;
            let _ = std::process::Command::new("cmd.exe")
                .arg("/c")
                .arg("pause")
                .status();
        }
    }
}

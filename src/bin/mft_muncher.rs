use mft_muncher::mft::MFT;
use std::time::Instant;

fn main() {
    let drive = r"C:\";

    let start = Instant::now();
    match MFT::new(drive) {
        Ok(mft) => {
            println!("got struct MFT in {} ns", start.elapsed().as_nanos());

            let start = Instant::now();
            match mft.get_all_ntfs_file_records() {
                Ok(records) => {
                    println!(
                        "mft.get_all_ntfs_file_records() returned {} records in {} ms",
                        records.len(),
                        start.elapsed().as_millis()
                    );

                    let _ = std::process::Command::new("cmd.exe")
                        .arg("/c")
                        .arg("pause")
                        .status();

                    //         for r in records {
                    //             let list: Vec<&mft_muncher::ntfs_attributes::NtfsAttribute> =
                    //                 r.1.attributes
                    //                     .iter()
                    //                     .filter(|x| x.header.attribute_type == 0x20)
                    //                     .collect();
                    //             if list.len() > 0 {
                    //                 dbg!(r);
                    //                 break;
                    //             }
                    //         }
                }
                Err(e) => {
                    eprintln!("ERROR from get_all_ntfs_file_records => {}", e);
                }
            }

            let frns: Vec<u64> = vec![
                102456891522680861,
                281474976731426,
                1407374883553285,
                61080069946295717,
                15762598695893097,
            ];
            let start = Instant::now();
            for frn in frns {
                let record = mft.get_record(frn).unwrap();
                match record.file_name() {
                    Some(x) => {
                        println!("frn {} name {}", frn, x);
                    }
                    None => {
                        println!("frn {} has no name", frn);
                    }
                }
            }
            println!("got 'em in {} ns", start.elapsed().as_nanos());
        }
        Err(e) => {
            println!("ERROR from MFT::new() =>  {}", e);
        }
    }

    println!("\n\n*** fin ***\n\n");
}

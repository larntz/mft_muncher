use mft_muncher::mft::MFT;
use std::time::Instant;

fn main() {
    let drive = r"C:\";

    let start = Instant::now();
    match MFT::new(drive) {
        Ok(mft) => {
            println!("got struct MFT in {} ns", start.elapsed().as_nanos());
            dbg!(&mft);

            let start = Instant::now();
            match mft.get_all_ntfs_file_records() {
                Ok(records) => {
                    println!(
                        "mft.get_all_ntfs_file_records() returned {} records in {} ms",
                        records.len(),
                        start.elapsed().as_millis()
                    );

                    for r in records {
                        let list: Vec<&mft_muncher::ntfs_attributes::NtfsAttribute> =
                            r.1.attributes
                                .iter()
                                .filter(|x| x.header.attribute_type == 0x20)
                                .collect();
                        if list.len() > 0 {
                            dbg!(r);
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("ERROR from get_all_ntfs_file_records => {}", e);
                }
            }

            // do some mft stuff
            // mft.get_record(1407374883553285);
            // mft.get_record(61080069946295717);
            // mft.get_record(15762598695893097);
            let _ = std::process::Command::new("cmd.exe")
                .arg("/c")
                .arg("pause")
                .status();
        }
        Err(e) => {
            println!("ERROR from MFT::new() =>  {}", e);
        }
    }

    println!("\n\n*** fin ***\n\n");
}

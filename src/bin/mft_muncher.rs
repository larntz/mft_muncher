use mft_muncher::mft::MFT;
use mft_muncher::ntfs_attributes::NtfsAttributeType;
use std::time::Instant;

fn main() {
    let drive = r"C:\";

    let start = Instant::now();
    match MFT::new(drive) {
        Ok(mft) => {
            println!("got struct MFT in {} ns", start.elapsed().as_nanos());

            // let record = mft.get_record(224335556438395287).unwrap();
            // dbg!(record);
            // let record = mft.get_record(42502721483355890).unwrap();
            // dbg!(record);

            // index_root testing
            // dbg!(mft.get_record(280349076803818884).unwrap());
            dbg!(mft.get_record(4222124650668069).unwrap());
            let _ = std::process::Command::new("cmd.exe")
                .arg("/c")
                .arg("pause")
                .status();

            // dbg!(mft.get_record(281474976710686).unwrap());
            // dbg!(mft.get_record(281474976710683).unwrap());
            // dbg!(mft.get_record(281474976710684).unwrap());
            // dbg!(mft.get_record(499336608684703848).unwrap());
            //dbg!(mft.get_record(32651290578518124).unwrap());

            // let start = Instant::now();
            match mft.get_all_ntfs_file_records() {
                Ok(records) => {
                    println!(
                        "mft.get_all_ntfs_file_records() returned {} records in {} ms",
                        records.len(),
                        start.elapsed().as_millis()
                    );

                    // let _ = std::process::Command::new("cmd.exe")
                    //     .arg("/c")
                    //     .arg("pause")
                    //     .status();

                    // todo answer question
                    // 1. Can a file record have more than one attribute list?
                    // todo after getting the attribute list we need to fetch the mft record (see below)
                    // and add that attribute date to the file record.
                    // for r in records {
                    //     if let Some(name) = r.1.file_name() {
                    //         if name == "02072020" {
                    //             // if name == "year-2019-created-2019-05-30T14_46_50.zip".to_string() || name == "en_windows_10_consumer_editions_version_2004_x64_dvd_8d28c5d7.iso".to_string() {
                    //             dbg!(&r);
                    //             println!("record has {} attributes", &r.1.attributes.len());
                    //             for attribute in &r.1.attributes {
                    //                 match &attribute.metadata {
                    //                     NtfsAttributeType::AttributeList(x) => {
                    //                         println!(
                    //                             "record attribute list has {} attributes",
                    //                             x.len()
                    //                         );
                    //                     }
                    //                     _ => {}
                    //                 }
                    //             }
                    //         }
                    //     }
                    //     // looking for non-resident attribute lists
                    //     // for attribute in
                    //     //     r.1.attributes
                    //     //         .iter()
                    //     //         .filter(|x| x.header.non_resident_flag == 1)
                    //     // {
                    //     //     match &attribute.metadata {
                    //     //         NtfsAttributeType::ReparsePoint(_) => {
                    //     //             dbg!(&r);
                    //     //             // for a in x.iter() {
                    //     //             //     if r.0 != a.base_frn {
                    //     //             //         let c_rec = mft.get_record(a.base_frn).unwrap();
                    //     //             //         dbg!(c_rec);
                    //     //             //     }
                    //     //             // }
                    //     //         }
                    //     //         _ => {}
                    //     //     }
                    //     // }
                    // }
                }
                Err(e) => {
                    eprintln!("ERROR from get_all_ntfs_file_records => {}", e);
                }
            }

            // reparse point testing
            // let frns: Vec<u64> = vec![154248287237444902, 49821070877794482, 81909218222809268];

            // physical
            // let frns: Vec<u64> = vec![
            //     102456891522680861,
            //     281474976731426,
            //     1407374883553285,
            //     61080069946295717,
            //     15762598695893097,
            // ];

            // virtual
            //let frns: Vec<u64> = vec![5348024558239138, 18014398509531529];
            // let start = Instant::now();
            // for frn in frns {
            //     let record = mft.get_record(frn).unwrap();
            //     match record.file_name() {
            //         Some(x) => {
            //             println!("frn {} name {}", frn, x);
            //         }
            //         None => {
            //             println!("frn {} has no name", frn);
            //         }
            //     }
            //     dbg!(record);
            // }
            // println!("got 'em in {} ns", start.elapsed().as_nanos());
        }
        Err(e) => {
            println!("ERROR from MFT::new() =>  {}", e);
        }
    }

    println!("\n\n*** fin ***\n\n");
}

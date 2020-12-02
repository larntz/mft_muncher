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
            // do some mft stuff
            mft.get_record(1407374883553285);
            println!("mft.get_record() in {} ns", start.elapsed().as_nanos());
        }
        Err(e) => {
            println!("ERROR: {}", e);
        }
    }
    // elevate process privileges (we require seBackupPrivilege and SeRestorePrivilege)
    //assert_security_privileges();

    // match get_volume_guid(drive) {
    //     Some(volume_root_guid) => {
    //         let start_time = Instant::now();
    //         let records = read_mft(&volume_root_guid).unwrap();
    //         let read_mft_duration = start_time.elapsed();
    //         println!(
    //             "received {} records in {}ms",
    //             records.len(),
    //             read_mft_duration.as_millis()
    //         );
    //         // let start_time = Instant::now();
    //         // let root_dir_frn = (records.get(&0).unwrap()).first().unwrap().frn;
    //         // for rec in records.iter().filter(|x| *x.0 == root_dir_frn) {
    //         //     println!("\n=> {} has {} children", rec.0, rec.1.len());
    //         //     for f in rec.1.iter() {
    //         //         println!(
    //         //             "{}{} is {} bytes [{}]",
    //         //             drive, f.file_name, f.real_size_bytes, f.frn,
    //         //         );
    //         //         for c_rec in records.iter().filter(|x| *x.0 == f.frn) {
    //         //             println!("\n=> {} has {} children", c_rec.0, c_rec.1.len());
    //         //             for cf in c_rec.1.iter() {
    //         //                 println!(
    //         //                     "{}{}\\{} is {} bytes [{}]",
    //         //                     drive, f.file_name, cf.file_name, cf.real_size_bytes, cf.frn,
    //         //                 );
    //         //             }
    //         //         }
    //         //     }
    //         // }
    //         // let search_files = start_time.elapsed();
    //         // println!("searched in {}ms", search_files.as_millis());

    //         let x = records.get(&281474976712649);
    //         // let x = records.get(&61080069946295717);
    //         dbg!(x);
    //         let y = records.get(&281474976712650);
    //         //let y = records.get(&15762598695893097);
    //         dbg!(y);

    //         let _ = std::process::Command::new("cmd.exe")
    //             .arg("/c")
    //             .arg("pause")
    //             .status();
    //     }
    //     None => {
    //         println!("drive {} volume guid not found", drive);
    //     }
    // }

    println!("\n\n*** fin ***\n\n");
}

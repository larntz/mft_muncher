use mft_muncher::unsafe_winapi_functions::{assert_security_privileges, get_volume_guid, read_mft};
use std::time::Instant;

fn main() {
    // elevate process privileges (we require seBackupPrivilege and SeRestorePrivilege)
    assert_security_privileges();

    let drive = r"c:\";
    match get_volume_guid(drive) {
        Some(volume_root_guid) => {
            let start_time = Instant::now();
            let records = read_mft(&volume_root_guid).unwrap();
            let read_mft_duration = start_time.elapsed();
            println!(
                "received a Vec with {} records in {}ms",
                records.len(),
                read_mft_duration.as_millis()
            );
            let start_time = Instant::now();
            let root_dir_frn = (records.get(&0).unwrap()).first().unwrap().reference_number;
            for rec in records.iter().filter(|x| *x.0 == root_dir_frn) {
                println!("\n=> {} has {} children", rec.0, rec.1.len());
                for f in rec.1.iter() {
                    println!(
                        "{}{} is {} bytes is_file {} [{}]",
                        drive,
                        f.name,
                        f.size_bytes,
                        f.is_file(),
                        f.reference_number,
                    );
                    for c_rec in records.iter().filter(|x| *x.0 == f.reference_number) {
                        println!("\n=> {} has {} children", c_rec.0, c_rec.1.len());
                        for cf in c_rec.1.iter() {
                            println!(
                                "{}{}\\{} is {} bytes and is_file {} [{}]",
                                drive,
                                f.name,
                                cf.name,
                                cf.size_bytes,
                                cf.is_file(),
                                cf.reference_number,
                            );
                        }
                    }
                }
            }
            let search_files = start_time.elapsed();
            println!("searched in {}ms", search_files.as_millis());
            let branding = records.get(&281474976712649);
            dbg!(branding);
            let basebrd = records.get(&281474976712650);
            dbg!(basebrd);

            let _ = std::process::Command::new("cmd.exe")
                .arg("/c")
                .arg("pause")
                .status();
        }
        None => {
            println!("drive {} volume guid not found", drive);
        }
    }

    println!("\nfinished");
}

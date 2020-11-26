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
            for rec in records.iter().filter(|x| *x.0 == 1407374883553285) {
                println!("{} has {} children", rec.0, rec.1.len());
                println!("{:#?}", rec.1);
            }
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

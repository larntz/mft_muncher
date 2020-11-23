use mft_muncher::unsafe_winapi_functions::{
    assert_security_privileges, get_file_read_handle, get_volume_guid, read_mft,
};

fn main() {
    // elevate process privileges (we require seBackupPrivilege and SeRestorePrivilege)
    assert_security_privileges();

    let drive = r"c:\";
    match get_volume_guid(drive) {
        Some(mut guid) => {
            guid.truncate(guid.len() - 1);
            let handle = get_file_read_handle(&guid).expect("somethin' ain't right");
            println!("handle looks like {:#?}", handle);
            let records = read_mft(handle);
            println!("received a Vec with {} records", records.len());
        }
        None => {
            println!("drive {} volume guid not found", drive);
        }
    }

    println!("\nfinished");
}

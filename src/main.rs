use mft_muncher::unsafe_winapi_functions::{get_file_read_handle, get_volume_guid};

fn main() {
    let drive = r"c:\";
    match get_volume_guid(drive) {
        Some(mut guid) => {
            println!("drive {} volume guid: {}", drive, guid);
            guid.truncate(guid.len() - 1);
            get_file_read_handle(&guid);
        }
        None => {
            println!("drive {} volume guid not found", drive);
        }
    }
}

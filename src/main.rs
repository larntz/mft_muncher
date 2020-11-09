use mft_muncher::unsafe_winapi_functions::{get_file_read_handle, get_volume_guid};

fn main() {
    let drive = r"c:\";
    match get_volume_guid(drive) {
        Some(guid) => {
            println!("drive {} volume guid: {}", drive, guid);
            get_file_read_handle("\\\\?\\Volume{3870b646-0000-0000-0000-602200000000}");
        }
        None => {
            println!("drive {} volume guid not found", drive);
        }
    }
}

use mft_muncher::unsafe_winapi_functions::get_volume_guid;

fn main() {
    let drive = "d:\\";
    match get_volume_guid(drive) {
        Some(guid) => {
            println!("drive {} volume guid: {}", drive, guid);
        },
        None => {
            println!("drive {} volume guid not found", drive);
        }

    }
}

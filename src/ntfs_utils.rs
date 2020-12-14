use std::convert::TryInto;
use std::io::Error;
use std::thread::current;
use winapi::ctypes::c_void;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::ReadFile;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::winnt::{HANDLE, LONGLONG};

pub fn read_clusters(lcn: u64, clusters: u8, data_length: u64, volume_handle: HANDLE) -> Vec<u8> {
    // for testing I will hard code this
    // todo use the bytes per sector from system
    let mut data: Vec<u8> = Vec::new();
    let mut temp_buffer = vec![0u8; 4096];
    let mut bytes_read = 0;

    let lcn = lcn * 4096;
    let mut current_cluster: u8 = 0;
    loop {
        let mut overlapped = unsafe {
            let mut over = std::mem::zeroed::<OVERLAPPED>();
            // mask them bits and shift 'em right on the high side
            over.u.s_mut().Offset = (lcn & 0x0000_0000_FFFF_FFFFu64) as u32;
            over.u.s_mut().OffsetHigh = ((lcn & 0xFFFF_FFFF_0000_0000u64) >> 32) as u32;
            over
        };
        let result = unsafe {
            ReadFile(
                volume_handle,
                temp_buffer.as_mut_ptr() as *mut c_void,
                temp_buffer.len() as u32,
                &mut bytes_read,
                &mut overlapped,
            )
        };

        if result == 0 {
            println!("last error {}", unsafe { GetLastError() });
            panic!("what happened?");
        }

        if data_length <= 4096 {
            temp_buffer.truncate(data_length as usize);
            data.append(&mut temp_buffer);
            break;
        } else {
            if data_length - (current_cluster as u64 * 4096) < 4096 {
                temp_buffer.truncate((data_length - (current_cluster as u64 * 4096)) as usize);
            }
            data.append(&mut temp_buffer);
        }

        current_cluster += 1;
        if current_cluster > clusters {
            break;
        }
    }
    data
}

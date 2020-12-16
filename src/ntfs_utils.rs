use std::convert::TryInto;
use std::io::Error;
use std::thread::current;
use winapi::ctypes::c_void;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::ReadFile;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::winnt::{HANDLE, LONGLONG};

pub fn load_data_runs(
    bytes: &[u8],
    vcn_count: u8,
    data_length: u64,
    volume_handle: HANDLE,
) -> Result<Vec<u8>, std::io::Error> {
    let mut total_run_length = 0;
    let mut x: Vec<u8> = Vec::new();
    let mut data_run_header: usize = 0;

    // loop to read all disk clusters
    while (total_run_length as u8) < vcn_count {
        let run_length_bytes = &bytes[data_run_header] % 0x10;
        let run_length_end = run_length_bytes / 1;
        let run_offset_bytes = &bytes[data_run_header] / 0x10;
        let run_offset_end = run_length_end + run_offset_bytes + 1;

        // get the run length
        let mut length_bytes = [0u8; 8];
        length_bytes[..run_length_bytes as usize]
            .copy_from_slice((&bytes[data_run_header as usize + 1..=run_length_end as usize]));
        let run_length = u64::from_le_bytes(length_bytes);
        total_run_length += run_length;

        // get the LCN
        let mut offset_bytes = [0u8; 8];
        offset_bytes[..run_offset_bytes as usize]
            .copy_from_slice(&bytes[2..run_offset_end as usize]);
        let offset = i64::from_le_bytes(offset_bytes);

        let mut clusters =
            read_clusters(offset as u64, run_length as u8, data_length, volume_handle)?;
        x.append(&mut clusters);
    }
    Ok(x)
}

pub fn read_clusters(
    lcn: u64,
    clusters: u8,
    data_length: u64,
    volume_handle: HANDLE,
) -> Result<Vec<u8>, std::io::Error> {
    // for testing I will hard code this 4096
    // todo use the bytes per sector from system
    let mut data: Vec<u8> = Vec::new();
    let mut temp_buffer = vec![0u8; 4096];
    let mut bytes_read = 0;

    let lcn = lcn * 4096;
    let mut current_cluster: u8 = 1;
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                std::io::Error::last_os_error(),
            ));
        }

        if data_length <= 4096 {
            temp_buffer.truncate(data_length as usize);
            data.append(&mut temp_buffer);
            break;
        } else {
            if data_length < (current_cluster as u64 * 4096) {
                temp_buffer.truncate(((current_cluster as u64 * 4096) - data_length) as usize);
            }
            data.append(&mut temp_buffer);
        }

        if current_cluster >= clusters {
            break;
        }
        current_cluster += 1;
    }
    Ok(data)
}

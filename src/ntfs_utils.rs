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
    let mut x: Vec<u8> = Vec::new();
    let mut data_run_header: usize = 0;
    let mut current_vcn: u8 = 0;
    let mut current_lcn_offset: i64 = 0;
    println!("[=====] data_length {}", data_length);
    println!("[=====] bytes length {},  {:x?}", &bytes.len(), &bytes);

    // loop to read all disk clusters
    while current_vcn < vcn_count {
        println!("[=====] start while loop");
        println!("[=====] current_vcn {}", current_vcn);
        if &bytes[data_run_header] == &0 {
            println!("[=====] exiting bc header {:#x}", &bytes[data_run_header]);
            break;
        }

        let run_length_bytes = &bytes[data_run_header] % 0x10;
        let run_length_end = run_length_bytes / 1;
        let run_offset_bytes = &bytes[data_run_header] / 0x10;
        let run_offset_end = run_length_end + run_offset_bytes + 1;
        println!("[=====] header {:#x}", &bytes[data_run_header]);
        println!(
            "[=====] run length length (byte count) {}",
            run_length_bytes
        );
        println!("[=====] run length end {}", run_length_end);
        println!(
            "[=====] run offset length (byte count) {}",
            run_offset_bytes
        );
        println!("[=====] run offset end {}", run_offset_end);
        println!(
            "[=====] run data {:x?} length {}",
            &bytes[data_run_header..data_run_header + run_offset_end as usize],
            &bytes[data_run_header..data_run_header + run_offset_end as usize].len()
        );

        // get the LCN offset (lcn = lcn_offset * cluster size (4096 by default))
        let mut lcn_offset_bytes = [0u8; 8];
        lcn_offset_bytes[..run_offset_bytes as usize].copy_from_slice(
            &bytes[data_run_header + run_length_end as usize + 1
                ..data_run_header + run_offset_end as usize],
        );
        println!("[=====] lcn_offset_bytes {:x?}", lcn_offset_bytes);
        let lcn_offset = i64::from_le_bytes(lcn_offset_bytes);
        println!(
            "[=====] lcn offset from last run {} ({:#x})",
            lcn_offset, lcn_offset
        );
        current_lcn_offset += lcn_offset;

        println!(
            "[=====] lcn offset / lcn {} ({:#x})",
            current_lcn_offset, current_lcn_offset
        );

        let mut clusters = read_clusters(current_lcn_offset as u64, data_length, volume_handle)?;
        x.append(&mut clusters);
        println!("[=====] x.len() {}", x.len());

        data_run_header += run_offset_end as usize;
        current_vcn += 1;
        println!("[=====] data_run_header {}", data_run_header);
    }
    println!("[=====] exit loop");
    Ok(x)
}

pub fn read_clusters(
    lcn: u64,
    data_length: u64,
    volume_handle: HANDLE,
) -> Result<Vec<u8>, std::io::Error> {
    // for testing I will hard code this 4096
    // todo use the bytes per sector from system
    let lcn = lcn * 4096;
    let mut data: Vec<u8> = Vec::new();
    let mut temp_buffer = vec![0u8; 4096];
    let mut bytes_read = 0;

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
        return match unsafe { GetLastError() } {
            // 38 is EOF
            38 => Ok(Vec::with_capacity(0)),
            // 87 is invalid parameter, but which one??
            87 => {
                println!("87");
                let _ = std::process::Command::new("cmd.exe")
                    .arg("/c")
                    .arg("pause")
                    .status();
                Ok(Vec::with_capacity(0))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                std::io::Error::last_os_error(),
            )),
        };
    }

    println!("[===========] bytes_read {}", bytes_read);
    Ok(temp_buffer)
    // data.append(&mut temp_buffer);
    // Ok(data)
}

extern crate winapi;

use self::winapi::um::winuser::CreateAcceleratorTableA;
use crate::to_wstring;
use std::io::Error;
use std::ptr;
use winapi::shared::minwindef::MAX_PATH;
use winapi::um::fileapi::{CreateFileW, GetVolumeNameForVolumeMountPointW, OPEN_EXISTING};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::winnt::LPCWSTR;
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GENERIC_READ};

pub fn get_volume_guid(drive: &str) -> Option<String> {
    unsafe {
        let volume_guid = &mut [0; MAX_PATH + 1];
        if GetVolumeNameForVolumeMountPointW(
            to_wstring(drive).as_ptr() as LPCWSTR,
            volume_guid.as_mut_ptr(),
            volume_guid.len() as u32,
        ) == 1
        {
            Some(String::from_utf16_lossy(
                &volume_guid[..volume_guid
                    .iter()
                    .position(|v| *v == 0)
                    .unwrap_or(volume_guid.len())],
            ))
        } else {
            None
        }
    }
}

pub fn get_file_read_handle(volume: &str) {
    unsafe {
        let handle = CreateFileW(
            volume.as_ptr() as LPCWSTR,
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            println!("ain't got no valid handle");
        }
    }
}

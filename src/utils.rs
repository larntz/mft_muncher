use std::convert::TryInto;
/// Converts a &str to a wide OsStr (utf16)
pub fn str_to_wstring(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn get_bytes_1(slice: &[u8]) -> Result<[u8; 1], std::io::Error> {
    if slice.len() >= 1 {
        let x: [u8; 1] = slice[..1].try_into().expect("this hurts");
        Ok(x)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }
}

pub fn get_bytes_2(slice: &[u8]) -> Result<[u8; 2], std::io::Error> {
    if slice.len() >= 1 {
        let x: [u8; 2] = slice[..2].try_into().expect("this hurts");
        Ok(x)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }
}

pub fn get_bytes_4(slice: &[u8]) -> Result<[u8; 4], std::io::Error> {
    if slice.len() >= 1 {
        let x: [u8; 4] = slice[..4].try_into().expect("this hurts");
        Ok(x)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }
}

pub fn get_bytes_8(slice: &[u8]) -> Result<[u8; 8], std::io::Error> {
    if slice.len() >= 1 {
        let x: [u8; 8] = slice[..8].try_into().expect("this hurts");
        Ok(x)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }
}

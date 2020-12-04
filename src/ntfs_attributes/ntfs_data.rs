use std::convert::TryInto;

/**
reference: [https://flatcap.org/linux-ntfs/ntfs/attributes/data.html](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html)

This is here for consistency, and possible future implementation.
I don't actually want any file data. Only information about the files.
Maybe someday there will be a reason to get the file data from here...
deleted file recovery or some kind of forensics.

But, for now, enjoy your empty NtfsData struct. TTFN

**/
#[derive(Debug)]
pub struct NtfsDataAttribute {}
impl NtfsDataAttribute {
    pub fn new(_bytes: &[u8]) -> Result<NtfsDataAttribute, std::io::Error> {
        Ok(NtfsDataAttribute {})
    }
}

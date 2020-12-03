# mft_muncher

The goal is to be able to examine disk usage quickly. To do that I am using win32 calls to read file information from the NTFS $MFT file. 

I may eventually make it a library for parsing the $MFT for other uses as well. For now that is out of scope.


## Ntfs File Record Construction Flow

1. get_ntfs_file_record(frn)
    - function gets file records from win32 function DeviceIoControl().
    
   1. Call NtfsFileRecord::new(bytes) to get a file record struct.
       - struct will contain the file record header and a list of attributes. 
       
      1. NtfsFileRecord will call NtfsFileRecordHeader::new() and then NtfsAttributeList::new()
         - NtfsFileRecordHeader::new() will construct the file record header.
         - NtfsAttributeList::new() will loop through all attached attributes and call NtfsAttribute::new() for each. 
         1. NtfsAttribute::new() will return an NtfsAttribute struct that contains the attribute header and attribute values.
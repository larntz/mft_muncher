# todo

Note: this project aims to be NTFSv3 compatible (2003/xp and newer)

(A) 12-3-2020 check version of ntfs volume before doing anything!! 
    * must be version 3.0 or 3.1

## lib.rs
x (A) 12-1-2020 add function to convert bytes into UTF16_LE so we can ditch the encoding_rs library
    * it's only used in one place, and I'd like to understand how to do it myself anyway. 
    * did this inline in ntfs_file_name.rs. Not sure I'll need it elsewhere.

## structs

x (A) 12-2-2020 move FileRecord and USN_RECORD structs to their own module.
(A) 12-2-2020 create struct for NTFS file record header
(A) 12-2-2020 create struct for NTFS attribute header
(A) 12-2-2020 create struct for $STANDARD_INFORMATION attribute
(A) 12-2-2020 create struct for $FILE_NAME attribute
(A) 12-2-2020 create struct for $DATA attribute
(A) 12-2-2020 create struct for $ATTRIBUTE_LIST

## struct impl

### impl NtfsAttributeCommonHeader

_These functions should be passed a &[u8] and go from there_

(A) 12-2-2020 create parse_standard_information() function
(A) 12-2-2020 create parse_file_name() function
(A) 12-2-2020 create parse_data() function
(A) 12-2-2020 create parse_attribute_list() function

## logic

(A) 12-2-2020 how to calculate sizes when we have $ATTRIBUTE_LIST pointing to multiple non-resident $DATA streams.
    * It seems that the size fields on those non-resident $DATA streams are always 0. May need to figure out how to work with __data runs__.

### Non-Resident $ATTRIBUTE_LIST

This appears to contain no information itself. The resident ATTRIBUTE_LIST has the additional attributes in the record. 

It seems that to get the additional attributes from a non-resident ATTRIBUTE_LIST you must look up the record specified in the base_frn of the non-resident ATTRIBUTE_LIST.

Question? What if there needs to be multiple other ATTRIBUTE_LISTS? Maybe the record pointed in the base_frn above contains an additional ATTRIBUTE_LIST plus other DATA (or whatever) ATTRIBUTES...

### Data Runs

See [https://flatcap.org/linux-ntfs/ntfs/concepts/data_runs.html](https://flatcap.org/linux-ntfs/ntfs/concepts/data_runs.html)

### $REPARSE_POINT Attributes

There are MS defined reparse points and third party reparse points.  The third party 
reparse points can be identified by types that could be unknown. Not sure how I might
be able to get the structure of the reparse point data or if I'd even want to...

In this app I think I will define the well known MS defined reparse points and save the 
third party ones as just "third party" with the type code and guid. 
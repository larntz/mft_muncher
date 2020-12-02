# todo

Note: this project aims to be NTFSv3 compatible (2003/xp and newer)

## lib.rs
(A) 12-1-2020 add function to convert bytes into UTF16_LE so we can ditch the encoding_rs library
    * it's only used in one place, and I'd like to understand how to do it myself anyway. 

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

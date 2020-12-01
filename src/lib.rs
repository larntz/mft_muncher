// /// This module represents a single ntfs file record.
// mod filerecord;

// /// This module represents the entire volume file system tree.  It contains unsafe code.
// pub mod fstree;

/// This module wraps unsafe function calls to winapi-rs. This is the only module
/// with unsafe code.
pub mod unsafe_winapi_functions;

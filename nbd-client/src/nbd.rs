/// NBD protocol constants for the client-side handshake.

// Handshake magic values
pub const NBD_MAGIC: u64 = 0x4e42444d41474943; // "NBDMAGIC"
pub const IHAVEOPT: u64 = 0x49484156454F5054; // "IHAVEOPT"
pub const NBD_OPT_REPLY_MAGIC: u64 = 0x3e889045565a9;

// Handshake flags (server → client)
pub const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
pub const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;

// Client flags
pub const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1 << 0;
pub const NBD_FLAG_C_NO_ZEROES: u32 = 1 << 1;

// Option types
pub const NBD_OPT_EXPORT_NAME: u32 = 1;

// Option reply types
pub const NBD_REP_ACK: u32 = 1;
pub const NBD_REP_INFO: u32 = 3;

// Info types
pub const NBD_INFO_EXPORT: u16 = 0;

// Linux kernel NBD ioctl numbers (from linux/nbd.h).
// These are architecture-independent on Linux.
pub const NBD_SET_SOCK: libc::c_ulong = 0xab00;
pub const NBD_SET_BLKSIZE: libc::c_ulong = 0xab01;
pub const NBD_SET_SIZE: libc::c_ulong = 0xab02;
pub const NBD_DO_IT: libc::c_ulong = 0xab03;
pub const NBD_CLEAR_SOCK: libc::c_ulong = 0xab04;
pub const NBD_CLEAR_QUE: libc::c_ulong = 0xab05;
pub const NBD_SET_SIZE_BLOCKS: libc::c_ulong = 0xab07;
pub const NBD_DISCONNECT: libc::c_ulong = 0xab08;
pub const NBD_SET_FLAGS: libc::c_ulong = 0xab0a;

// Transmission flags we might receive
pub const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
pub const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
pub const NBD_FLAG_SEND_TRIM: u16 = 1 << 5;

// Transmission-phase magic numbers (kernel ↔ server framing).
pub const NBD_REQUEST_MAGIC: u32 = 0x25609513;
pub const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x67446698;

// Command types (lower 16 bits of the request type field).
pub const NBD_CMD_READ: u16 = 0;
pub const NBD_CMD_WRITE: u16 = 1;
pub const NBD_CMD_DISC: u16 = 2;
pub const NBD_CMD_FLUSH: u16 = 3;
pub const NBD_CMD_TRIM: u16 = 4;

/// Result of the NBD negotiation: the export parameters.
pub struct ExportInfo {
    pub size: u64,
    pub flags: u16,
}

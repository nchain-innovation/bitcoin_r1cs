use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Result as IoResult;

/// Convert u64 to var_int
pub fn u64_to_var_int(length: usize) -> IoResult<Vec<u8>> {
    let mut s: Vec<u8> = Vec::new();
    if length <= 252 {
        s.write_u8(length as u8)?;
    } else if length <= 0xffff {
        s.write_u8(0xfd)?;
        s.write_u16::<LittleEndian>(length as u16)?;
    } else if length <= 0xffffffff {
        s.write_u8(0xfe)?;
        s.write_u32::<LittleEndian>(length as u32)?;
    } else {
        s.write_u8(0xff)?;
        s.write_u64::<LittleEndian>(length as u64)?;
    }

    Ok(s)
}

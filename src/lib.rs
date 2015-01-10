#![crate_name="capstone"]
#![crate_type="rlib"]
#![experimental]

extern crate libc;
extern crate core;
extern crate serialize;

use libc::{c_int, c_void, size_t};
use std::ffi::c_str_to_bytes;
use std::mem;
use std::raw::Slice;
use std::str::from_utf8;

mod ll;

#[cfg(test)]
mod tests;

#[derive(Copy, Show)]
pub enum Arch {
    Arm = 0,
    Arm64,
    MIPS,
    X86,
    PowerPC,
    Sparc,
    SystemZ,
    XCore,
}

bitflags!(
    #[derive(Show)]
    flags Mode: u32 {
        const MODE_LITTLE_ENDIAN= 0,
        const MODE_ARM          = 0,
        const MODE_16           = 1 << 1,
        const MODE_32           = 1 << 2,
        const MODE_64           = 1 << 3,
        const MODE_THUMB        = 1 << 4,
        const MODE_MCLASS       = 1 << 5,
        const MODE_V8           = 1 << 6,
        const MODE_MICRO        = 1 << 4,
        const MODE_MIPS3        = 1 << 5,
        const MODE_MIPS32R6     = 1 << 6,
        const MODE_MIPSGP64     = 1 << 7,
        const MODE_V9           = 1 << 4,
        const MODE_BIG_ENDIAN   = 1 << 31,
        const MODE_MIPS32       = 1 << 2,
        const MODE_MIPS64       = 1 << 3,
    }
);

#[derive(Copy, Show)]
pub enum Opt {
    Syntax = 1,
    Detail,
    Mode,
    // OptMem
}

#[derive(Show)]
pub struct Error {
    pub code: uint,
    pub desc: Option<String>,
}

impl Error {
    fn new(err: uint) -> Error {
        unsafe {
            let cstr = ll::cs_strerror(err as i32) as *const i8;
            Error{ code: err, desc: Some(String::from_utf8_lossy(c_str_to_bytes(&cstr)).to_string()) }
        }
    }
}

pub struct Insn {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
}

pub struct Engine {
    handle: *const c_void
}

impl Engine {
    pub fn new(arch: Arch, mode: Mode) -> Result<Engine, Error> {
        let mut handle : *const c_void = 0 as *const c_void;
        unsafe {
            match ll::cs_open(arch as c_int, mode.bits as c_int, &mut handle) {
                0 => Ok(Engine{handle: handle}),
                e => Err(Error::new(e as uint)),
            }
        }
    }

    pub fn set_option(&self, option: Opt, value: uint) -> Result<(), Error> {
        unsafe {
            match ll::cs_option(self.handle, option as c_int, value as size_t) {
                0 => Ok(()),
                e => Err(Error::new(e as uint)),
            }
        }
    }

    pub fn disasm(&self, code: &[u8], addr: u64, count: uint) -> Result<Vec<Insn>, Error> {
        unsafe {
            let mut cinsnptr : *mut ll::cs_insn = 0 as *mut ll::cs_insn;
            match ll::cs_disasm(self.handle, code.as_ptr(), code.len() as size_t, addr, count as size_t, &mut cinsnptr) {
                0 => Err(Error::new(self.errno())),
                n => {
                    let mut v = Vec::new();
                    let cinsn : &[ll::cs_insn] = mem::transmute(Slice{ data: cinsnptr, len: n as uint});
                    v.extend(cinsn.iter().map(|ci| {
                        Insn{
                            addr:     ci.address,
                            bytes:    range(0, ci.size as uint).map(|i| ci.bytes[i]).collect(),
                            mnemonic: from_utf8(c_str_to_bytes(&(ci.mnemonic.as_ptr() as *const i8))).unwrap_or("<invalid utf8>").to_string(),
                            op_str:   from_utf8(c_str_to_bytes(&(ci.op_str.as_ptr() as *const i8))).unwrap_or("<invalid utf8>").to_string(),
                        }

                    }));
                    ll::cs_free(cinsnptr, n);
                    Ok(v)
                },
            }
        }
    }

    fn errno(&self) -> uint {
        unsafe{ ll::cs_errno(self.handle) as uint }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe{ ll::cs_close(&mut self.handle) };
    }
}

pub fn version() -> (int, int) {
    let mut major : c_int = 0;
    let mut minor : c_int = 0;
    unsafe{ ll::cs_version(&mut major, &mut minor);}
    (major as int, minor as int)
}

pub fn supports(arch: Arch) -> bool {
    unsafe{ ll::cs_support(arch as c_int) == 0 }
}

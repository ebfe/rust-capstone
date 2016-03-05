#![crate_name="capstone"]
#![crate_type="rlib"]

extern crate libc;

#[macro_use] extern crate bitflags;

use libc::{c_int, c_void, size_t};
use std::ffi::CStr;

mod ll;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug)]
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
    pub flags Mode: u32 {
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

#[derive(Clone, Copy, Debug)]
pub enum Opt {
    Syntax = 1,
    Detail,
    Mode,
    // OptMem
}

#[derive(Debug)]
pub struct Error {
    pub code: usize,
    pub desc: Option<String>,
}

impl Error {
    fn new(err: usize) -> Error {
        unsafe {
            let cstr = ll::cs_strerror(err as i32) as *const _;
            Error{ code: err, desc: Some(String::from_utf8_lossy(CStr::from_ptr(cstr).to_bytes()).to_string()) }
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
                e => Err(Error::new(e as usize)),
            }
        }
    }

    pub fn set_option(&self, option: Opt, value: usize) -> Result<(), Error> {
        unsafe {
            match ll::cs_option(self.handle, option as c_int, value as size_t) {
                0 => Ok(()),
                e => Err(Error::new(e as usize)),
            }
        }
    }

    pub fn disasm(&self, code: &[u8], addr: u64, count: usize) -> Result<Vec<Insn>, Error> {
        unsafe {
            let mut cinsnptr : *mut ll::cs_insn = 0 as *mut ll::cs_insn;
            match ll::cs_disasm(self.handle, code.as_ptr(), code.len() as size_t, addr, count as size_t, &mut cinsnptr) {
                0 => Err(Error::new(self.errno())),
                n => {
                    let mut v = Vec::new();
                    let cinsn : &[ll::cs_insn] = std::slice::from_raw_parts(cinsnptr, n as usize);
                    v.extend(cinsn.iter().map(|ci| {
                        Insn{
                            addr:     ci.address,
                            bytes:    (0..ci.size as usize).map(|i| ci.bytes[i]).collect(),
                            mnemonic: String::from_utf8_lossy(CStr::from_ptr(ci.mnemonic.as_ptr() as *const _).to_bytes()).to_string(),
                            op_str:   String::from_utf8_lossy(CStr::from_ptr(ci.op_str.as_ptr() as *const _).to_bytes()).to_string(),
                        }

                    }));
                    ll::cs_free(cinsnptr, n);
                    Ok(v)
                },
            }
        }
    }

    fn errno(&self) -> usize {
        unsafe{ ll::cs_errno(self.handle) as usize }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe{ ll::cs_close(&mut self.handle) };
    }
}

pub fn version() -> (isize, isize) {
    let mut major : c_int = 0;
    let mut minor : c_int = 0;
    unsafe{ ll::cs_version(&mut major, &mut minor);}
    (major as isize, minor as isize)
}

pub fn supports(arch: Arch) -> bool {
    unsafe{ ll::cs_support(arch as c_int) != 0 }
}

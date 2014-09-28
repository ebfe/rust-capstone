#![crate_name="capstone"]
#![crate_type="rlib"]
#![experimental]

#![feature(globs)]

extern crate libc;
extern crate core;
extern crate serialize;

#[cfg(test)]
extern crate debug;

use libc::{c_int, c_void, size_t};
use std::c_str::CString;
use std::c_vec::CVec;

mod ll;

#[cfg(test)]
mod tests;

pub enum Arch {
	ArchArm = 0,
	ArchArm64,
	ArchMIPS,
	ArchX86,
	ArchPPC,
}

bitflags!(
	flags Mode: u32 {
		static ModeLittleEndian = 0,
		static ModeArm          = 0,
		static Mode16           = 1 << 1,
		static Mode32           = 1 << 2,
		static Mode64           = 1 << 3,
		static ModeThumb        = 1 << 4,
		static ModeMicro        = 1 << 4,
		static ModeN64          = 1 << 5,
		static ModeBigEndian    = 1 << 31
	}
)

pub enum Opt {
    OptSyntax = 1,
    OptDetail,
    OptMode,
    // OptMem
}

pub struct Error {
    pub code: uint,
    pub desc: Option<String>,
}

impl Error {
    fn new(err: uint) -> Error {
        unsafe {
            match CString::new(ll::cs_strerror(err as i32), false).as_str() {
                Some(s) =>
                    Error{ code: err, desc: Some(s.to_string()) },
                None =>
                    Error{ code: err, desc: None },
            }
        }
    }
}

pub struct Engine {
	handle: *const c_void
}

pub struct Insn {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
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
            let mut insn : *mut ll::cs_insn = 0 as *mut ll::cs_insn;
            match ll::cs_disasm_ex(self.handle, code.as_ptr(), code.len() as size_t, addr, count as size_t, &mut insn) {
                0 => Err(Error::new(self.errno())),
                n => {
                    let mut v = Vec::new();
                    let cinsn = CVec::new(insn, n as uint);
                    for &i in cinsn.as_slice().iter() {
                        let bvec : Vec<u8> = Vec::from_fn(i.size as uint, |n| { i.bytes[n] });
                        let mnem : String = CString::new(i.mnemonic.as_ptr() as *const i8, false).as_str().unwrap().to_string();
                        let ops : String = CString::new(i.op_str.as_ptr() as *const i8, false).as_str().unwrap().to_string();

                        v.push(Insn{
                            addr: i.address,
                            bytes: bvec,
                            mnemonic: mnem,
                            op_str: ops,
                        });
                    }
                    ll::cs_free(insn, n);
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

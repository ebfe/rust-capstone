#![crate_id="capstone#0.2.1"]
#![crate_type="rlib"]

extern crate libc;
extern crate core;
extern crate serialize;

use libc::{c_int, c_void, size_t};
use std::c_str::CString;
use std::c_vec::CVec;

mod ll;

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
		static ModeArm = 1 << 1,
		static Mode16 = 1 << 2,
		static Mode32 = 1 << 3,
		static Mode64 = 1 << 4,
		static ModeThumb = 1 << 4,
		static ModeMicro = 1 << 4,
		static ModeN64 = 1 << 5,
		static ModeBigEndian = 1 << 31
	}
)

pub enum Opt {
    OptSyntax = 1,
    OptDetail,
    OptMode,
    // OptMem
}

pub struct Engine {
	handle: *c_void 
}

pub struct Insn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: ~str,
    pub op_str: ~str, 
}

impl Engine {
    pub fn new(arch: Arch, mode: Mode) -> Result<Engine, uint> {
        let mut handle : *c_void = 0 as *c_void;
        unsafe { 
            match ll::cs_open(arch as c_int, mode.bits as c_int, &mut handle) {
                0 => Ok(Engine{handle: handle}),
                err => Err(err as uint),
            }
        }
    }

    pub fn set_option(&self, option: Opt, value: uint) -> Result<(), uint> {
        unsafe {
            match ll::cs_option(self.handle, option as c_int, value as size_t) {
                0 => Ok(()),
                e => Err(e as uint),
            }
        }
    }

    pub fn disasm(&self, code: &[u8], addr: u64, count: uint) -> Result<Vec<Insn>, uint> {
        unsafe {
            let mut insn : *mut ll::cs_insn = 0 as *mut ll::cs_insn;
            match ll::cs_disasm_ex(self.handle, code.as_ptr(), code.len() as size_t, addr, count as u64, &mut insn) {
                0 => Err(self.errno()),
                n => {
                    let mut v = Vec::new();
                    let cinsn = CVec::new(insn, n as uint);
                    for &i in cinsn.as_slice().iter() {
                        let bvec : Vec<u8> = Vec::from_fn(i.size as uint, |n| { i.bytes[n] });
                        let mnem : ~str = CString::new(i.mnemonic.as_ptr() as *i8, false).as_str().unwrap().to_owned();
                        let ops : ~str = CString::new(i.op_str.as_ptr() as *i8, false).as_str().unwrap().to_owned();

                        v.push(Insn{
                            address: i.address,
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

pub fn version() -> (int, int) {
    let mut major : c_int = 0;
    let mut minor : c_int = 0;
    unsafe{ ll::cs_version(&mut major, &mut minor);}
    (major as int, minor as int)
}

pub fn supports(arch: Arch) -> bool {
    unsafe{ ll::cs_support(arch as c_int) == 0 }
}

#[cfg(test)]
mod tests {
    #[test]
    pub fn test_version() {
        use super::version;
        println!("{:?}", super::version());
    }

    #[test]
    pub fn test_engine_new() {
        use super::{Engine, ArchX86, Mode32};

        match Engine::new(ArchX86, Mode32) {
            Ok(e) => println!("{:?}", e),
            Err(err) => fail!("Engine::new error: {:?}", err),
        }
    }

    #[test]
    pub fn test_engine_disasm() {
        use super::{Engine, ArchX86, Mode32};
        match Engine::new(ArchX86, Mode32) {
            Ok(e) => {
                match e.disasm(&[0xeb, 0xfe, 0x90, 0x90], 0x80000000, 5) {
                    Ok(insn) => {
                        println!("{:?}", insn);
                        for i in range(0, insn.len()) {
                            let c = insn.get(i);
                            println!("{:x}: {} {} {}", c.address,  c.bytes, c.mnemonic, c.op_str);
                        }
                    }
                    Err(err) => fail!("Engine::disasm error: {:?}", err)
                }
            }
            Err(err) => fail!("Engine::new error: {:?}", err)
        }
    }
}

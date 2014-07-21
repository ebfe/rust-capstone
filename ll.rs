#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libc::{c_char, c_int, c_uint, c_void, size_t};

pub type c_bool = c_int;

pub type csh = *const c_void;
pub type cs_err = c_int;
pub type cs_opt_type = c_int;

pub struct cs_insn {
    pub id: c_uint,
    pub address: u64,
    pub size: u16,
    pub bytes: [u8, ..16u],
    pub mnemonic: [u8, ..32u],
    pub op_str: [u8, ..160u],
    pub detail: *const c_void,
}

#[link(name = "capstone")]
extern "C" {
    pub fn cs_version(major: *mut c_int, minor: *mut c_int) -> c_uint;
    pub fn cs_support(query: c_int) -> c_bool;
    pub fn cs_open(arch: c_int, mode: c_int, handle: *mut csh) -> cs_err;
    pub fn cs_close(handle: *mut csh) -> cs_err;
    pub fn cs_option(handle: csh, _type: cs_opt_type, value: size_t) -> cs_err;
    pub fn cs_errno(handle: csh) -> cs_err;
    pub fn cs_strerror(code: cs_err) -> *const c_char;
    pub fn cs_disasm_ex(handle: csh, code: *const u8, code_size: size_t, address: u64, count: size_t, insn: *mut *mut cs_insn) -> size_t;
    pub fn cs_free(insn: *mut cs_insn, count: size_t);
    pub fn cs_reg_name(handle: csh, reg_id: c_uint) -> *const c_char;
    pub fn cs_insn_name(handle: csh, insn_id: c_uint) -> *const c_char;
    pub fn cs_insn_group(handle: csh, insn: *mut cs_insn, group_id: c_uint) -> c_bool;
    pub fn cs_reg_read(handle: csh, insn: *mut cs_insn, reg_id: c_uint) -> c_bool;
    pub fn cs_reg_write(handle: csh, insn: *mut cs_insn, reg_id: c_uint) -> c_bool;
    pub fn cs_op_count(handle: csh, insn: *mut cs_insn, op_type: c_uint) -> c_int;
    pub fn cs_op_index(handle: csh, insn: *mut cs_insn, op_type: c_uint, position: c_uint) -> c_int;
}

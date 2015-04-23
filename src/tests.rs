use super::*;

#[test]
pub fn test_engine_disasm() {
    struct Test {
        arch: Arch,
        mode: Mode,
        opts: Vec<(Opt, usize)>,
        code: Vec<u8>,
        insn: Vec<Insn>,
    };

    let tests = vec![
        Test{
            arch: Arch::X86,
            mode: MODE_16,
            opts: vec![],
            code: vec![0x8d, 0x4c, 0x32, 0x08, 0x01, 0xd8, 0x81, 0xc6, 0x34, 0x12, 0x00, 0x00],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x8d, 0x4c, 0x32, ],
                mnemonic: "lea".to_string(),
                op_str: "cx, word ptr [si + 0x32]".to_string(),
            }, Insn{
                addr: 0x1003,
                bytes: vec![0x08, 0x01, ],
                mnemonic: "or".to_string(),
                op_str: "byte ptr [bx + di], al".to_string(),
            }, Insn{
                addr: 0x1005,
                bytes: vec![0xd8, 0x81, 0xc6, 0x34, ],
                mnemonic: "fadd".to_string(),
                op_str: "dword ptr [bx + di + 0x34c6]".to_string(),
            }, Insn{
                addr: 0x1009,
                bytes: vec![0x12, 0x00, ],
                mnemonic: "adc".to_string(),
                op_str: "al, byte ptr [bx + si]".to_string(),
            }],
        }, Test{
            arch: Arch::X86,
            mode: MODE_32,
            opts: vec![(Opt::Syntax, 2 /*ATT*/)],
            code: vec![0x8d, 0x4c, 0x32, 0x08, 0x01, 0xd8, 0x81, 0xc6, 0x34, 0x12, 0x00, 0x00],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x8d, 0x4c, 0x32, 0x08, ],
                mnemonic: "leal".to_string(),
                op_str: "8(%edx, %esi), %ecx".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0x01, 0xd8, ],
                mnemonic: "addl".to_string(),
                op_str: "%ebx, %eax".to_string(),
            }, Insn{
                addr: 0x1006,
                bytes: vec![0x81, 0xc6, 0x34, 0x12, 0x00, 0x00, ],
                mnemonic: "addl".to_string(),
                op_str: "$0x1234, %esi".to_string(),
            }],
        }, Test{
            arch: Arch::X86,
            mode: MODE_32,
            opts: vec![],
            code: vec![0x8d, 0x4c, 0x32, 0x08, 0x01, 0xd8, 0x81, 0xc6, 0x34, 0x12, 0x00, 0x00],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x8d, 0x4c, 0x32, 0x08, ],
                mnemonic: "lea".to_string(),
                op_str: "ecx, dword ptr [edx + esi + 8]".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0x01, 0xd8, ],
                mnemonic: "add".to_string(),
                op_str: "eax, ebx".to_string(),
            }, Insn{
                addr: 0x1006,
                bytes: vec![0x81, 0xc6, 0x34, 0x12, 0x00, 0x00, ],
                mnemonic: "add".to_string(),
                op_str: "esi, 0x1234".to_string(),
            }],
        }, Test{
            arch: Arch::X86,
            mode: MODE_64,
            opts: vec![],
            code: vec![0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x55, ],
                mnemonic: "push".to_string(),
                op_str: "rbp".to_string(),
            }, Insn{
                addr: 0x1001,
                bytes: vec![0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00, ],
                mnemonic: "mov".to_string(),
                op_str: "rax, qword ptr [rip + 0x13b8]".to_string(),
            }],
        }, Test{
            arch: Arch::Arm,
            mode: MODE_ARM|MODE_LITTLE_ENDIAN,
            opts: vec![],
            code: vec![0xed, 0xff, 0xff, 0xeb, 0x04, 0xe0, 0x2d, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x83, 0x22, 0xe5, 0xf1, 0x02, 0x03, 0x0e, 0x00, 0x00, 0xa0, 0xe3, 0x02, 0x30, 0xc1, 0xe7, 0x00, 0x00, 0x53, 0xe3],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0xed, 0xff, 0xff, 0xeb, ],
                mnemonic: "bl".to_string(),
                op_str: "#0xfbc".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0x04, 0xe0, 0x2d, 0xe5, ],
                mnemonic: "str".to_string(),
                op_str: "lr, [sp, #-4]!".to_string(),
            }, Insn{
                addr: 0x1008,
                bytes: vec![0x00, 0x00, 0x00, 0x00, ],
                mnemonic: "andeq".to_string(),
                op_str: "r0, r0, r0".to_string(),
            }, Insn{
                addr: 0x100c,
                bytes: vec![0xe0, 0x83, 0x22, 0xe5, ],
                mnemonic: "str".to_string(),
                op_str: "r8, [r2, #-0x3e0]!".to_string(),
            }, Insn{
                addr: 0x1010,
                bytes: vec![0xf1, 0x02, 0x03, 0x0e, ],
                mnemonic: "mcreq".to_string(),
                op_str: "p2, #0, r0, c3, c1, #7".to_string(),
            }, Insn{
                addr: 0x1014,
                bytes: vec![0x00, 0x00, 0xa0, 0xe3, ],
                mnemonic: "mov".to_string(),
                op_str: "r0, #0".to_string(),
            }, Insn{
                addr: 0x1018,
                bytes: vec![0x02, 0x30, 0xc1, 0xe7, ],
                mnemonic: "strb".to_string(),
                op_str: "r3, [r1, r2]".to_string(),
            }, Insn{
                addr: 0x101c,
                bytes: vec![0x00, 0x00, 0x53, 0xe3, ],
                mnemonic: "cmp".to_string(),
                op_str: "r3, #0".to_string(),
            }],
        }, Test{
            arch: Arch::Arm,
            mode: MODE_THUMB,
            opts: vec![],
            code: vec![0x4f, 0xf0, 0x00, 0x01, 0xbd, 0xe8, 0x00, 0x88, 0xd1, 0xe8, 0x00, 0xf0],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x4f, 0xf0, 0x00, 0x01, ],
                mnemonic: "mov.w".to_string(),
                op_str: "r1, #0".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0xbd, 0xe8, 0x00, 0x88, ],
                mnemonic: "pop.w".to_string(),
                op_str: "{fp, pc}".to_string(),
            }, Insn{
                addr: 0x1008,
                bytes: vec![0xd1, 0xe8, 0x00, 0xf0, ],
                mnemonic: "tbb".to_string(),
                op_str: "[r1, r0]".to_string(),
            }],
        }, Test{
            arch: Arch::Arm,
            mode: MODE_ARM,
            opts: vec![],
            // ARM: Cortex-A15 + NEON,
            code: vec![0x10, 0xf1, 0x10, 0xe7, 0x11, 0xf2, 0x31, 0xe7, 0xdc, 0xa1, 0x2e, 0xf3, 0xe8, 0x4e, 0x62, 0xf3],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x10, 0xf1, 0x10, 0xe7, ],
                mnemonic: "sdiv".to_string(),
                op_str: "r0, r0, r1".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0x11, 0xf2, 0x31, 0xe7, ],
                mnemonic: "udiv".to_string(),
                op_str: "r1, r1, r2".to_string(),
            }, Insn{
                addr: 0x1008,
                bytes: vec![0xdc, 0xa1, 0x2e, 0xf3, ],
                mnemonic: "vbit".to_string(),
                op_str: "q5, q15, q6".to_string(),
            }, Insn{
                addr: 0x100c,
                bytes: vec![0xe8, 0x4e, 0x62, 0xf3, ],
                mnemonic: "vcgt.f32".to_string(),
                op_str: "q10, q9, q12".to_string(),
            }],
        }, Test{
            arch: Arch::Arm,
            mode: MODE_THUMB,
            opts: vec![],
            // THUMB,
            code: vec![0x70, 0x47, 0xeb, 0x46, 0x83, 0xb0, 0xc9, 0x68],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x70, 0x47, ],
                mnemonic: "bx".to_string(),
                op_str: "lr".to_string(),
            }, Insn{
                addr: 0x1002,
                bytes: vec![0xeb, 0x46, ],
                mnemonic: "mov".to_string(),
                op_str: "fp, sp".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0x83, 0xb0, ],
                mnemonic: "sub".to_string(),
                op_str: "sp, #0xc".to_string(),
            }, Insn{
                addr: 0x1006,
                bytes: vec![0xc9, 0x68, ],
                mnemonic: "ldr".to_string(),
                op_str: "r1, [r1, #0xc]".to_string(),
            }],
        }, Test{
            arch: Arch::MIPS,
            mode: MODE_32| MODE_BIG_ENDIAN,
            opts: vec![],
            // MIPS-32 (Big-endian),
            code: vec![0x0c, 0x10, 0x00, 0x97, 0x00, 0x00, 0x00, 0x00, 0x24, 0x02, 0x00, 0x0c, 0x8f, 0xa2, 0x00, 0x00, 0x34, 0x21, 0x34, 0x56],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x0c, 0x10, 0x00, 0x97, ],
                mnemonic: "jal".to_string(),
                op_str: "0x40025c".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0x00, 0x00, 0x00, 0x00, ],
                mnemonic: "nop".to_string(),
                op_str: "".to_string(),
            }, Insn{
                addr: 0x1008,
                bytes: vec![0x24, 0x02, 0x00, 0x0c, ],
                mnemonic: "addiu".to_string(),
                op_str: "$v0, $zero, 0xc".to_string(),
            }, Insn{
                addr: 0x100c,
                bytes: vec![0x8f, 0xa2, 0x00, 0x00, ],
                mnemonic: "lw".to_string(),
                op_str: "$v0, ($sp)".to_string(),
            }, Insn{
                addr: 0x1010,
                bytes: vec![0x34, 0x21, 0x34, 0x56, ],
                mnemonic: "ori".to_string(),
                op_str: "$at, $at, 0x3456".to_string(),
            }],
        }, Test{
            arch: Arch::MIPS,
            mode: MODE_64| MODE_LITTLE_ENDIAN,
            opts: vec![],
            // MIPS-64-EL (Little-endian),
            code: vec![0x56, 0x34, 0x21, 0x34, 0xc2, 0x17, 0x01, 0x00],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x56, 0x34, 0x21, 0x34, ],
                mnemonic: "ori".to_string(),
                op_str: "$at, $at, 0x3456".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0xc2, 0x17, 0x01, 0x00, ],
                mnemonic: "srl".to_string(),
                op_str: "$v0, $at, 0x1f".to_string(),
            }],
        }, Test{
            arch: Arch::Arm64,
            mode: MODE_ARM,
            opts: vec![],
            code: vec![0x21, 0x7c, 0x02, 0x9b, 0x21, 0x7c, 0x00, 0x53, 0x00, 0x40, 0x21, 0x4b, 0xe1, 0x0b, 0x40, 0xb9, 0x10, 0x20, 0x21, 0x1e],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x21, 0x7c, 0x02, 0x9b, ],
                mnemonic: "mul".to_string(),
                op_str: "x1, x1, x2".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0x21, 0x7c, 0x00, 0x53, ],
                mnemonic: "lsr".to_string(),
                op_str: "w1, w1, #0".to_string(),
            }, Insn{
                addr: 0x1008,
                bytes: vec![0x00, 0x40, 0x21, 0x4b, ],
                mnemonic: "sub".to_string(),
                op_str: "w0, w0, w1, uxtw".to_string(),
            }, Insn{
                addr: 0x100c,
                bytes: vec![0xe1, 0x0b, 0x40, 0xb9, ],
                mnemonic: "ldr".to_string(),
                op_str: "w1, [sp, #8]".to_string(),
            }, Insn{
                addr: 0x1010,
                bytes: vec![0x10, 0x20, 0x21, 0x1e, ],
                mnemonic: "fcmpe".to_string(),
                op_str: "s0, s1".to_string(),
            }],
        }, Test{
            arch: Arch::PowerPC,
            mode: MODE_BIG_ENDIAN,
            opts: vec![],
            code: vec![0x80, 0x20, 0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x10, 0x43, 0x23, 0x0e, 0xd0, 0x44, 0x00, 0x80, 0x4c, 0x43, 0x22, 0x02, 0x2d, 0x03, 0x00, 0x80, 0x7c, 0x43, 0x20, 0x14, 0x7c, 0x43, 0x20, 0x93, 0x4f, 0x20, 0x00, 0x21, 0x4c, 0xc8, 0x00, 0x21],
            insn: vec![Insn{
                addr: 0x1000,
                bytes: vec![0x80, 0x20, 0x00, 0x00, ],
                mnemonic: "lwz".to_string(),
                op_str: "r1, (0)".to_string(),
            }, Insn{
                addr: 0x1004,
                bytes: vec![0x80, 0x3f, 0x00, 0x00, ],
                mnemonic: "lwz".to_string(),
                op_str: "r1, (r31)".to_string(),
            }, Insn{
                addr: 0x1008,
                bytes: vec![0x10, 0x43, 0x23, 0x0e, ],
                mnemonic: "vpkpx".to_string(),
                op_str: "v2, v3, v4".to_string(),
            }, Insn{
                addr: 0x100c,
                bytes: vec![0xd0, 0x44, 0x00, 0x80, ],
                mnemonic: "stfs".to_string(),
                op_str: "f2, 0x80(r4)".to_string(),
            }, Insn{
                addr: 0x1010,
                bytes: vec![0x4c, 0x43, 0x22, 0x02, ],
                mnemonic: "crand".to_string(),
                op_str: "2, 3, 4".to_string(),
            }, Insn{
                addr: 0x1014,
                bytes: vec![0x2d, 0x03, 0x00, 0x80, ],
                mnemonic: "cmpwi".to_string(),
                op_str: "cr2, r3, 0x80".to_string(),
            }, Insn{
                addr: 0x1018,
                bytes: vec![0x7c, 0x43, 0x20, 0x14, ],
                mnemonic: "addc".to_string(),
                op_str: "r2, r3, r4".to_string(),
            }, Insn{
                addr: 0x101c,
                bytes: vec![0x7c, 0x43, 0x20, 0x93, ],
                mnemonic: "mulhd.".to_string(),
                op_str: "r2, r3, r4".to_string(),
            }, Insn{
                addr: 0x1020,
                bytes: vec![0x4f, 0x20, 0x00, 0x21, ],
                mnemonic: "bdnzlrl+".to_string(),
                op_str: "".to_string(),
            }, Insn{
                addr: 0x1024,
                bytes: vec![0x4c, 0xc8, 0x00, 0x21, ],
                mnemonic: "bgelrl-".to_string(),
                op_str: "cr2".to_string(),
            }],
        },
    ];

    for (i, test) in tests.iter().enumerate() {
        println!("test case #{} / {:?} {:?}", i, test.arch, test.mode);
        match Engine::new(test.arch, test.mode) {
            Ok(e) => {
                for &(opt, val) in test.opts.iter() {
                    match e.set_option(opt, val) {
                        Ok(_) => (),
                        Err(err) => panic!("#{} Engine::set_option({:?}, {:?}) failed: {:?}\n", i, opt, val, err),
                    }
                }
                match e.disasm(test.code.as_ref(), 0x1000, 0) {
                    Ok(insns) => {
                        assert!(insns.len() == test.insn.len());
                        for (out, expected) in insns.iter().zip(test.insn.iter()) {
                            println!("out: {:x}\t{}\t{}", out.addr, out.mnemonic, out.op_str);
                            println!("exp: {:x}\t{}\t{}", expected.addr, expected.mnemonic, expected.op_str);
                            assert!(out.addr == expected.addr);
                            assert!(out.bytes == expected.bytes);
                            assert!(out.mnemonic == expected.mnemonic);
                            assert!(out.op_str == expected.op_str);
                        }
                    }
                    Err(err) => {
                        panic!("#{} Engine::disasm failed: {:?} {:?}", i, err.code, err.desc);
                    }
                }
            },
            Err(err) => {
                panic!("#{} Engine::new failed: {:?} {:?}", i, err.code, err.desc);
            }
        }
    }
}

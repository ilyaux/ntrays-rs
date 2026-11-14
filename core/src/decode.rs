//! Bounded decoder for the six legacy opcode forms missing from IDA's x64 decoder.
//! No bytes are patched. LKGS keeps its ModRM/SIB so the SDK can load the 16-bit operand.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Decoded {
    pub kind: u32, // ERETS, ERETU, LKGS, WRMSRNS, INVLPGB, TLBSYNC
    pub size: u32,
    pub modrm: u32,
    pub sib: u32, // 256: no SIB
    pub rex: u32,
    pub segment: u32,
    pub address32: u32,
    pub disp_offset: u32,
    pub disp_size: u32,
    pub displacement: i64,
}

pub fn decode(bytes: &[u8]) -> Option<Decoded> {
    let bytes = &bytes[..bytes.len().min(15)];
    let mut d = Decoded { sib: 256, ..Decoded::default() };
    let (mut p, mut repeat, mut operand16) = (0, 0, false);
    loop {
        match *bytes.get(p)? {
            0xf0 => return None,
            b @ (0xf2 | 0xf3) => { if repeat != 0 { return None; } repeat = b; d.rex = 0; }
            0x66 => { if operand16 { return None; } operand16 = true; d.rex = 0; }
            0x67 => { if d.address32 != 0 { return None; } d.address32 = 1; d.rex = 0; }
            b @ (0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65) => {
                if d.segment != 0 { return None; } d.segment = b as u32; d.rex = 0;
            }
            b @ 0x40..=0x4f => d.rex = b as u32,
            _ => break,
        }
        p += 1;
    }
    if bytes.get(p) != Some(&0x0f) { return None; }
    let opcode = *bytes.get(p + 1)?;
    let extension = *bytes.get(p + 2)?;
    p += 3;
    if opcode == 0x01 && extension == 0xca && matches!(repeat, 0xf2 | 0xf3) {
        d.kind = u32::from(repeat == 0xf3);
    } else if opcode == 0x01 && repeat == 0 && !operand16 && d.segment == 0 && d.rex == 0 {
        d.kind = match extension {
            0xc6 if d.address32 == 0 => 3,
            0xfe => 4,
            0xff if d.address32 == 0 => 5,
            _ => return None,
        };
    } else if opcode == 0x00 && repeat == 0xf2 && extension & 0x38 == 0x30 {
        d.kind = 2;
        d.modrm = extension as u32;
        let (mode, rm) = (extension >> 6, extension & 7);
        if mode != 3 {
            if rm == 4 { d.sib = *bytes.get(p)? as u32; p += 1; }
            d.disp_size = match mode {
                0 if rm == 5 || (rm == 4 && d.sib & 7 == 5) => 4,
                1 => 1,
                2 => 4,
                _ => 0,
            };
            if d.disp_size != 0 {
                d.disp_offset = p as u32;
                d.displacement = if d.disp_size == 1 { *bytes.get(p)? as i8 as i64 }
                    else { i32::from_le_bytes(bytes.get(p..p + 4)?.try_into().ok()?) as i64 };
                p += d.disp_size as usize;
            }
        }
    } else { return None; }
    d.size = p as u32;
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_opcodes_and_fred_polarity() {
        for (bytes, kind) in [(&[0xf2,0x0f,0x01,0xca][..],0), (&[0xf3,0x0f,0x01,0xca],1),
            (&[0x0f,0x01,0xc6],3), (&[0x0f,0x01,0xfe],4), (&[0x0f,0x01,0xff],5)] {
            let d = decode(bytes).unwrap(); assert_eq!((d.kind,d.size),(kind,bytes.len() as u32));
            for end in 0..bytes.len() { assert!(decode(&bytes[..end]).is_none()); }
        }
        assert_eq!(decode(&[0x67,0x0f,0x01,0xfe]).unwrap().address32,1);
        assert_eq!(decode(&[0x66,0xf3,0x48,0x0f,0x01,0xca]).unwrap().kind,1);
    }

    #[test]
    fn lkgs_registers_sib_displacements_and_address_size() {
        assert_eq!(decode(&[0xf2,0x41,0x0f,0x00,0xf0]).unwrap().rex,0x41);
        let d=decode(&[0x67,0xf2,0x43,0x0f,0x00,0x74,0x88,0xf0]).unwrap();
        assert_eq!((d.kind,d.size,d.sib,d.displacement,d.disp_offset,d.address32),(2,8,0x88,-16,7,1));
        for bytes in [&[0xf2,0x0f,0x00,0x35,0,0,0,0][..], &[0xf2,0x0f,0x00,0x34,0x25,0,0,0,0],
            &[0xf2,0x0f,0x00,0xb0,1,2,3,4]] {
            assert_eq!(decode(bytes).unwrap().size,bytes.len() as u32);
            for end in 0..bytes.len() { assert!(decode(&bytes[..end]).is_none()); }
        }
        assert_eq!(std::mem::size_of::<Decoded>(),48);
    }

    #[test]
    fn other_opcodes_unsupported_prefixes_and_truncation_are_not_claimed() {
        for bytes in [&[0x0f,0x01,0xca][..], &[0xf0,0xf2,0x0f,0x01,0xca], &[0xf2,0xf3,0x0f,0x01,0xca],
            &[0xf3,0x0f,0x00,0xf0], &[0xf2,0x0f,0x00,0xf8], &[0xf2,0x0f,0x01,0xc6], &[0x0f,0x01,0xc5],
            &[0x66,0x0f,0x01,0xfe], &[0x65,0x0f,0x01,0xff], &[0xc5,0xfb,0xf6,0xc0]] { assert!(decode(bytes).is_none()); }
        assert!(decode(&[0x66;16]).is_none());
    }
}

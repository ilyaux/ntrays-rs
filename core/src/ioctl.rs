//! I/O control codes (`CTL_CODE`): decoding a 32-bit value into its fields and back.
//!
//! Decoding only explains a number. Whether a value is an IOCTL the driver actually handles is a separate,
//! evidence-backed question (where the value is compared against `IoControlCode`); a value that merely decodes
//! cleanly — an NTSTATUS, a flag mask, any DWORD — is not a discovery.
//!
//! Layout ([Microsoft: Defining I/O Control Codes](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes)),
//! as built by `CTL_CODE(DeviceType, Function, Method, Access)` in winioctl.h:
//!
//! | bits  | field                                                        |
//! |-------|--------------------------------------------------------------|
//! | 31    | Common: set for vendor device types (part of DeviceType)    |
//! | 16-31 | DeviceType (16 bits, including Common)                       |
//! | 14-15 | RequiredAccess                                               |
//! | 13    | Custom: set for vendor function codes (part of Function)     |
//! | 2-13  | Function (12 bits, including Custom)                         |
//! | 0-1   | TransferType (Method)                                        |

use std::fmt;

use crate::ioctl_device_types::DEVICE_TYPES;

/// How the I/O manager passes buffers for this code (`METHOD_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    Buffered = 0,
    InDirect = 1,
    OutDirect = 2,
    Neither = 3,
}

impl Method {
    pub fn from_bits(bits: u32) -> Self {
        [
            Method::Buffered,
            Method::InDirect,
            Method::OutDirect,
            Method::Neither,
        ][(bits & 3) as usize]
    }

    pub fn name(self) -> &'static str {
        match self {
            Method::Buffered => "METHOD_BUFFERED",
            Method::InDirect => "METHOD_IN_DIRECT",
            Method::OutDirect => "METHOD_OUT_DIRECT",
            Method::Neither => "METHOD_NEITHER",
        }
    }
}

/// Access the caller's handle must have (`RequiredAccess`), a 2-bit mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Access(u8);

impl Access {
    pub const ANY: Access = Access(0);
    pub const READ: Access = Access(1);
    pub const WRITE: Access = Access(2);

    pub fn from_bits(bits: u32) -> Self {
        Access((bits & 3) as u8)
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    /// `FILE_ANY_ACCESS`, `FILE_READ_DATA`, `FILE_WRITE_DATA` or `FILE_READ_DATA | FILE_WRITE_DATA`.
    pub fn name(self) -> &'static str {
        match self.0 {
            0 => "FILE_ANY_ACCESS",
            1 => "FILE_READ_DATA",
            2 => "FILE_WRITE_DATA",
            _ => "FILE_READ_DATA | FILE_WRITE_DATA",
        }
    }
}

/// The fields of one I/O control code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CtlCode {
    /// Device type, all 16 bits as passed to `CTL_CODE` (values with bit 15 set are vendor-defined).
    pub device_type: u16,
    /// Function code, all 12 bits (values with bit 11 set are vendor-defined).
    pub function: u16,
    pub method: Method,
    pub access: Access,
}

/// Why a value is not decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtlCodeError {
    /// A 64-bit value whose upper half is neither zero nor a sign extension of bit 31: decoding its low half would
    /// silently truncate.
    NotA32BitValue(u64),
    /// A field passed to `encode` does not fit its bits.
    FieldOutOfRange {
        field: &'static str,
        value: u32,
        max: u32,
    },
}

impl fmt::Display for CtlCodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CtlCodeError::NotA32BitValue(v) => write!(f, "0x{v:X} is not a 32-bit control code"),
            CtlCodeError::FieldOutOfRange { field, value, max } => {
                write!(f, "{field} 0x{value:X} does not fit (max 0x{max:X})")
            }
        }
    }
}

impl std::error::Error for CtlCodeError {}

impl CtlCode {
    /// Splits a 32-bit control code into its fields. Every 32-bit value decodes; see the module docs for why
    /// that says nothing about whether it is an IOCTL.
    pub fn decode(code: u32) -> Self {
        CtlCode {
            device_type: (code >> 16) as u16,
            function: ((code >> 2) & 0xFFF) as u16,
            method: Method::from_bits(code),
            access: Access::from_bits(code >> 14),
        }
    }

    /// Decodes a value read from a wider operand (a 64-bit register, an `int`). Accepts zero-extended and
    /// sign-extended 32-bit values (`0xFFFFFFFF80002000` from `movsxd`); refuses anything else rather than
    /// truncating it.
    pub fn decode_value(value: u64) -> Result<Self, CtlCodeError> {
        let high = (value >> 32) as u32;
        let sign_extended = high == u32::MAX && value & 0x8000_0000 != 0;
        if high != 0 && !sign_extended {
            return Err(CtlCodeError::NotA32BitValue(value));
        }
        Ok(Self::decode(value as u32))
    }

    /// `CTL_CODE(DeviceType, Function, Method, Access)`, with every field checked against its width.
    pub fn encode(
        device_type: u32,
        function: u32,
        method: u32,
        access: u32,
    ) -> Result<u32, CtlCodeError> {
        let check = |field, value: u32, max: u32| {
            if value > max {
                Err(CtlCodeError::FieldOutOfRange { field, value, max })
            } else {
                Ok(value)
            }
        };
        let d = check("DeviceType", device_type, 0xFFFF)?;
        let f = check("Function", function, 0xFFF)?;
        let m = check("Method", method, 3)?;
        let a = check("Access", access, 3)?;
        Ok((d << 16) | (a << 14) | (f << 2) | m)
    }

    /// The 32-bit code these fields make.
    pub fn value(&self) -> u32 {
        ((self.device_type as u32) << 16)
            | ((self.access.0 as u32) << 14)
            | ((self.function as u32) << 2)
            | self.method as u32
    }

    /// Common bit: the device type is vendor-defined (0x8000 and above).
    pub fn is_vendor_device_type(&self) -> bool {
        self.device_type & 0x8000 != 0
    }

    /// Custom bit: the function code is vendor-defined (0x800 and above).
    pub fn is_vendor_function(&self) -> bool {
        self.function & 0x800 != 0
    }

    /// `FILE_DEVICE_*` name of the device type, if the Windows SDK defines one.
    pub fn device_type_name(&self) -> Option<&'static str> {
        DEVICE_TYPES
            .binary_search_by_key(&self.device_type, |&(v, _)| v)
            .ok()
            .map(|i| DEVICE_TYPES[i].1)
    }
}

/// `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)`, with hex for unnamed device types.
impl fmt::Display for CtlCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CTL_CODE(")?;
        match self.device_type_name() {
            Some(name) => write!(f, "{name}")?,
            None => write!(f, "0x{:04X}", self.device_type)?,
        }
        write!(
            f,
            ", 0x{:03X}, {}, {})",
            self.function,
            self.method.name(),
            self.access.name()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The examples from the WDI request (ntrays#482): fixtures for the decoder, not results of analyzing a file.
    #[test]
    fn user_examples() {
        for (code, function) in [(0x222004, 0x801), (0x222008, 0x802), (0x22200C, 0x803)] {
            let c = CtlCode::decode(code);
            assert_eq!(
                (c.device_type, c.function, c.method, c.access),
                (0x22, function, Method::Buffered, Access::ANY)
            );
            assert!(c.is_vendor_function() && !c.is_vendor_device_type());
            assert_eq!(c.device_type_name(), Some("FILE_DEVICE_UNKNOWN"));
            assert_eq!(
                c.to_string(),
                format!(
                    "CTL_CODE(FILE_DEVICE_UNKNOWN, 0x{function:03X}, METHOD_BUFFERED, FILE_ANY_ACCESS)"
                )
            );
        }
    }

    #[test]
    fn every_method_and_access_round_trips() {
        let names = [
            "FILE_ANY_ACCESS",
            "FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_READ_DATA | FILE_WRITE_DATA",
        ];
        for method in 0..4 {
            for access in 0..4 {
                let code = CtlCode::encode(0x22, 0x900, method, access).unwrap();
                let c = CtlCode::decode(code);
                assert_eq!((c.method as u32, c.access.bits() as u32), (method, access));
                assert_eq!(c.access.name(), names[access as usize]);
                assert_eq!(c.value(), code);
            }
        }
    }

    #[test]
    fn field_boundaries_round_trip() {
        for (d, f) in [
            (0, 0),
            (0x7FFF, 0x7FF),
            (0x8000, 0x800),
            (0xFFFF, 0xFFF),
            (0x8123, 0x001),
        ] {
            let code = CtlCode::encode(d, f, 3, 3).unwrap();
            let c = CtlCode::decode(code);
            assert_eq!((c.device_type as u32, c.function as u32), (d, f));
            assert_eq!(c.is_vendor_device_type(), d >= 0x8000);
            assert_eq!(c.is_vendor_function(), f >= 0x800);
            assert_eq!(c.value(), code);
        }
        // Every bit of a 32-bit value lands in exactly one field.
        for code in [0u32, u32::MAX, 0x8000_0000, 0x0000_2000, 0xDEAD_BEEF] {
            assert_eq!(CtlCode::decode(code).value(), code);
        }
    }

    #[test]
    fn encode_rejects_fields_that_do_not_fit() {
        assert!(CtlCode::encode(0x1_0000, 0, 0, 0).is_err());
        assert!(CtlCode::encode(0, 0x1000, 0, 0).is_err());
        assert!(CtlCode::encode(0, 0, 4, 0).is_err());
        assert!(CtlCode::encode(0, 0, 0, 4).is_err());
    }

    #[test]
    fn wide_values_are_not_truncated() {
        assert_eq!(CtlCode::decode_value(0x222004).unwrap().value(), 0x222004);
        // movsxd of a vendor code with bit 31 set.
        assert_eq!(
            CtlCode::decode_value(0xFFFF_FFFF_8000_2000)
                .unwrap()
                .value(),
            0x8000_2000
        );
        assert_eq!(
            CtlCode::decode_value(0xFFFF_FFFF_0000_2000),
            Err(CtlCodeError::NotA32BitValue(0xFFFF_FFFF_0000_2000))
        );
        assert_eq!(
            CtlCode::decode_value(0x1_0022_2004),
            Err(CtlCodeError::NotA32BitValue(0x1_0022_2004))
        );
    }

    #[test]
    fn device_type_names_and_hex_fallback() {
        assert_eq!(
            CtlCode::decode(0x0007_0000).device_type_name(),
            Some("FILE_DEVICE_DISK")
        );
        assert_eq!(
            CtlCode::decode(0x002D_1400).to_string(),
            "CTL_CODE(FILE_DEVICE_MASS_STORAGE, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)"
        );
        let vendor = CtlCode::decode(CtlCode::encode(0x8123, 0x801, 3, 3).unwrap());
        assert_eq!(vendor.device_type_name(), None);
        assert_eq!(
            vendor.to_string(),
            "CTL_CODE(0x8123, 0x801, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)"
        );
        let names = &DEVICE_TYPES;
        assert!(
            names.windows(2).all(|w| w[0].0 < w[1].0),
            "table must stay sorted"
        );
    }
}

//! Versioned per-database options. A single value is committed atomically by the SDK adapter.

pub const COMPONENTS: u32 = 0x3f;
const MAGIC: u64 = 0x4e54_5253_0000_0000;
const VERSION: u64 = 1 << 24;
const PAYLOAD_MASK: u64 = 3 | ((COMPONENTS as u64) << 8) | (3 << 16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    pub components: u32,
    pub fold_hvl: bool,
    /// 0 = errors, 1 = informational messages, 2 = per-pass diagnostics.
    pub log_level: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self { enabled: true, components: COMPONENTS, fold_hvl: false, log_level: 1 }
    }
}

impl Settings {
    pub fn component(self, index: u32) -> bool {
        self.enabled && index < 6 && self.components & (1 << index) != 0
    }

    pub fn encode(self) -> Result<u64, &'static str> {
        if self.components & !COMPONENTS != 0 || self.log_level > 2 {
            return Err("invalid NtRays settings");
        }
        Ok(MAGIC | VERSION | u64::from(self.enabled) | (u64::from(self.fold_hvl) << 1)
            | ((self.components as u64) << 8) | ((self.log_level as u64) << 16))
    }

    pub fn decode(value: u64) -> Result<Self, &'static str> {
        if value & 0xffff_ffff_ff00_0000 != MAGIC | VERSION {
            return Err("unsupported NtRays settings format");
        }
        let payload = value & 0x00ff_ffff;
        if payload & !PAYLOAD_MASK != 0 {
            return Err("unknown NtRays settings flags");
        }
        let settings = Self {
            enabled: payload & 1 != 0,
            fold_hvl: payload & 2 != 0,
            components: ((payload >> 8) & COMPONENTS as u64) as u32,
            log_level: ((payload >> 16) & 3) as u32,
        };
        settings.encode()?;
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_supported_options_roundtrip_without_aliasing() {
        for components in 0..=COMPONENTS {
            for log_level in 0..=2 {
                for enabled in [false, true] {
                    for fold_hvl in [false, true] {
                        let settings = Settings { enabled, components, fold_hvl, log_level };
                        assert_eq!(Settings::decode(settings.encode().unwrap()), Ok(settings));
                    }
                }
            }
        }
    }

    #[test]
    fn defaults_and_master_switch_gate_every_component() {
        let mut settings = Settings::default();
        assert!(!settings.fold_hvl);
        for component in 0..6 { assert!(settings.component(component)); }
        assert!(!settings.component(6) && !settings.component(u32::MAX));
        settings.enabled = false;
        for component in 0..6 { assert!(!settings.component(component)); }
        settings.enabled = true;
        settings.components = 1 << 1;
        assert!(settings.component(1) && !settings.component(0));
    }

    #[test]
    fn future_corrupt_and_reserved_settings_are_rejected() {
        let good = Settings::default().encode().unwrap();
        for value in [0, good ^ (1 << 32), good ^ (3 << 24), good | (1 << 7), good | (1 << 14), good | (3 << 16)] {
            assert!(Settings::decode(value).is_err(), "{value:x}");
        }
        assert!(Settings { components: 1 << 6, ..Settings::default() }.encode().is_err());
        assert!(Settings { log_level: 3, ..Settings::default() }.encode().is_err());
    }
}

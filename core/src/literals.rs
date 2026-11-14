//! Contexts where a four-byte Windows pool tag can be printed as a C character literal.

pub fn pool_tag_argument(name: &str, value: u64) -> Option<usize> {
    let tag = u32::try_from(value).ok()?;
    if !tag.to_be_bytes().iter().all(|b| (b' '..=b'~').contains(b)) {
        return None;
    }
    let name = name.strip_prefix("__imp_").unwrap_or(name);
    match name {
        "ExAllocatePool2" | "ExAllocatePool3" | "ExAllocatePoolWithTag"
        | "ExAllocatePoolWithQuotaTag" | "ExAllocatePoolWithTagPriority" => Some(2),
        "ExFreePoolWithTag" => Some(1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_require_a_known_api_and_four_printable_bytes() {
        let tag = u32::from_be_bytes(*b"Tag1") as u64;
        for name in ["ExAllocatePool2", "ExAllocatePool3", "ExAllocatePoolWithTag",
            "ExAllocatePoolWithQuotaTag", "ExAllocatePoolWithTagPriority", "__imp_ExAllocatePool2"] {
            assert_eq!(pool_tag_argument(name, tag), Some(2));
        }
        assert_eq!(pool_tag_argument("ExFreePoolWithTag", tag), Some(1));
        for name in ["ExAllocatePool", "MyExAllocatePool2", "ExAllocatePool2Extra", "other"] {
            assert_eq!(pool_tag_argument(name, tag), None);
        }
        for value in [0, tag | (1 << 32), u32::from_be_bytes(*b"Tag\0") as u64,
            u32::from_be_bytes([b'A', b'B', b'C', 127]) as u64] {
            assert_eq!(pool_tag_argument("ExAllocatePool2", value), None);
        }
    }
}

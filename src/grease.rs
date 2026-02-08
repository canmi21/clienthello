/* src/grease.rs */

/// Check whether a `u16` value is a GREASE value defined in RFC 8701.
///
/// GREASE values have identical high and low bytes matching `0x_A`, producing the set
/// `{0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA}`.
///
/// ```
/// assert!(clienthello::is_grease(0x0A0A));
/// assert!(clienthello::is_grease(0xFAFA));
/// assert!(!clienthello::is_grease(0x1301));
/// ```
#[must_use]
pub fn is_grease(value: u16) -> bool {
	(value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec::Vec;

	#[test]
	fn all_grease_values() {
		let expected: Vec<u16> = (0..16u16).map(|i| (i << 12) | (i << 4) | 0x0A0A).collect();
		for &v in &expected {
			assert!(is_grease(v), "{v:#06x} should be GREASE");
		}
	}

	#[test]
	fn non_grease() {
		assert!(!is_grease(0x0000));
		assert!(!is_grease(0x1301));
		assert!(!is_grease(0x0017));
		assert!(!is_grease(0xFFFF));
	}

	#[test]
	fn mixed_nibbles_are_not_grease() {
		// Values where low nibbles are both 0xA but high nibbles differ
		// are NOT valid GREASE values per RFC 8701.
		assert!(!is_grease(0x0A1A));
		assert!(!is_grease(0x1A0A));
		assert!(!is_grease(0x2A5A));
		assert!(!is_grease(0x3AFA));
		assert!(!is_grease(0xFA0A));
	}
}

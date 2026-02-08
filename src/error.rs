/* src/error.rs */

/// Errors produced during TLS ClientHello parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
	/// Input buffer does not contain enough bytes.
	#[error("buffer too short: need {need} bytes, have {have}")]
	BufferTooShort {
		/// Minimum bytes required.
		need: usize,
		/// Bytes actually available.
		have: usize,
	},

	/// TLS record content type is not Handshake (`0x16`).
	#[error("unexpected content type: expected 0x16 (Handshake), got {0:#04x}")]
	NotHandshakeRecord(u8),

	/// Handshake message type is not ClientHello (`0x01`).
	#[error("unexpected handshake type: expected 0x01 (ClientHello), got {0:#04x}")]
	NotClientHello(u8),

	/// A required field was truncated in the input.
	#[error("truncated {field}")]
	Truncated {
		/// Name of the truncated field.
		field: &'static str,
	},
}

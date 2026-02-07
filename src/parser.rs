/* src/parser.rs */

use alloc::vec::Vec;

use crate::ClientHello;
use crate::Error;
use crate::extension::{Extension, parse_extension};
use crate::grease::is_grease;
use crate::reader::Reader;

/// Parse a TLS ClientHello from a raw Handshake message.
///
/// The input should begin with the handshake type byte `0x01`.
/// This is the format seen in QUIC CRYPTO frames where the record
/// layer has already been removed.
///
/// # Errors
///
/// Returns an error when the data is truncated, the handshake type
/// is not ClientHello, or any field cannot be decoded.
///
/// ```
/// # fn build() -> Vec<u8> {
/// #     let mut d = vec![0x01, 0x00, 0x00, 0x29, 0x03, 0x03];
/// #     d.extend_from_slice(&[0u8; 32]);
/// #     d.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
/// #     d
/// # }
/// # let data = build();
/// let hello = clienthello::parse(&data).unwrap();
/// assert_eq!(hello.legacy_version, 0x0303);
/// ```
pub fn parse(data: &[u8]) -> Result<ClientHello<'_>, Error> {
	if data.is_empty() {
		return Err(Error::BufferTooShort { need: 1, have: 0 });
	}
	let mut r = Reader::new(data);
	let hs_type = r.read_u8("handshake type")?;
	if hs_type != 0x01 {
		return Err(Error::NotClientHello(hs_type));
	}
	let body_len = r.read_u24("handshake length")? as usize;
	let body = r.read_bytes(body_len, "handshake body")?;
	parse_body(body)
}

/// Parse a TLS ClientHello from a TLS record-layer message.
///
/// The input should begin with the content type byte `0x16`
/// (Handshake). The record layer header is stripped before the
/// contained handshake message is forwarded to [`parse`].
///
/// # Errors
///
/// Returns an error when the record layer is invalid, the data is
/// truncated, or the inner handshake is not a ClientHello.
///
/// ```
/// # fn build() -> Vec<u8> {
/// #     let mut d = vec![0x16, 0x03, 0x01, 0x00, 0x2D];
/// #     d.push(0x01); d.extend_from_slice(&[0x00, 0x00, 0x29]);
/// #     d.extend_from_slice(&[0x03, 0x03]);
/// #     d.extend_from_slice(&[0u8; 32]);
/// #     d.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
/// #     d
/// # }
/// # let data = build();
/// let hello = clienthello::parse_from_record(&data).unwrap();
/// assert_eq!(hello.cipher_suites, vec![0x1301]);
/// ```
pub fn parse_from_record(data: &[u8]) -> Result<ClientHello<'_>, Error> {
	if data.len() < 5 {
		return Err(Error::BufferTooShort {
			need: 5,
			have: data.len(),
		});
	}
	let mut r = Reader::new(data);
	let content_type = r.read_u8("record content type")?;
	if content_type != 0x16 {
		return Err(Error::NotHandshakeRecord(content_type));
	}
	let _version = r.read_u16("record protocol version")?;
	let record_len = r.read_u16("record length")? as usize;
	let handshake = r.read_bytes(record_len, "record payload")?;
	parse(handshake)
}

fn parse_body<'a>(data: &'a [u8]) -> Result<ClientHello<'a>, Error> {
	let mut r = Reader::new(data);
	let mut has_grease = false;

	let legacy_version = r.read_u16("legacy version")?;
	let random = r.read_bytes(32, "client random")?;

	let sid_len = r.read_u8("session ID length")? as usize;
	let session_id = r.read_bytes(sid_len, "session ID")?;

	let cipher_suites = parse_cipher_suites(&mut r, &mut has_grease)?;

	let comp_len = r.read_u8("compression methods length")? as usize;
	let compression_methods = r.read_bytes(comp_len, "compression methods")?;

	let extensions = if r.remaining() >= 2 {
		parse_extensions(&mut r, &mut has_grease)?
	} else {
		Vec::new()
	};

	Ok(ClientHello {
		legacy_version,
		random,
		session_id,
		cipher_suites,
		compression_methods,
		extensions,
		has_grease,
	})
}

fn parse_cipher_suites(r: &mut Reader<'_>, has_grease: &mut bool) -> Result<Vec<u16>, Error> {
	let len = r.read_u16("cipher suites length")? as usize;
	let cs_data = r.read_bytes(len, "cipher suites data")?;
	let mut inner = Reader::new(cs_data);
	let mut suites = Vec::new();
	while inner.remaining() >= 2 {
		let val = inner.read_u16("cipher suite")?;
		if is_grease(val) {
			*has_grease = true;
		} else {
			suites.push(val);
		}
	}
	Ok(suites)
}

fn parse_extensions<'a>(
	r: &mut Reader<'a>,
	has_grease: &mut bool,
) -> Result<Vec<Extension<'a>>, Error> {
	let len = r.read_u16("extensions length")? as usize;
	let ext_data = r.read_bytes(len, "extensions data")?;
	let mut inner = Reader::new(ext_data);
	let mut extensions = Vec::new();
	while inner.remaining() >= 4 {
		let type_id = inner.read_u16("extension type")?;
		let ext_len = inner.read_u16("extension length")? as usize;
		let ext_body = inner.read_bytes(ext_len, "extension body")?;
		extensions.push(parse_extension(type_id, ext_body, has_grease)?);
	}
	Ok(extensions)
}

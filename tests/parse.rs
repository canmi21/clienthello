/* tests/parse.rs */
#![allow(missing_docs)]

mod helpers;

use clienthello::{Error, Extension, is_grease, parse, parse_from_record};

#[test]
fn minimal_raw_handshake() {
	let data = helpers::minimal_raw();
	let hello = parse(&data).unwrap();
	assert_eq!(hello.legacy_version, 0x0303);
	assert_eq!(hello.random, &[0u8; 32]);
	assert!(hello.session_id.is_empty());
	assert_eq!(hello.cipher_suites, vec![0x1301]);
	assert_eq!(hello.compression_methods, &[0x00]);
	assert!(hello.extensions.is_empty());
	assert!(!hello.has_grease);
}

#[test]
fn minimal_record_layer() {
	let raw = helpers::minimal_raw();
	let record = helpers::wrap_record(&raw);
	let hello = parse_from_record(&record).unwrap();
	assert_eq!(hello.legacy_version, 0x0303);
	assert_eq!(hello.cipher_suites, vec![0x1301]);
}

#[test]
fn full_parse_raw() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();

	assert_eq!(hello.legacy_version, 0x0303);
	assert_eq!(hello.random, &[0xAB; 32]);
	assert_eq!(hello.session_id, &[0xCD; 32]);
	assert_eq!(hello.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
	assert!(hello.has_grease);
}

#[test]
fn full_parse_record() {
	let raw = helpers::full_raw();
	let record = helpers::wrap_record(&raw);
	let hello = parse_from_record(&record).unwrap();
	assert_eq!(hello.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
	assert!(hello.has_grease);
}

#[test]
fn sni_extraction() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	assert_eq!(hello.server_name(), Some("example.com"));
}

#[test]
fn no_sni() {
	let data = helpers::minimal_raw();
	let hello = parse(&data).unwrap();
	assert_eq!(hello.server_name(), None);
}

#[test]
fn alpn_extraction() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	let alpn = hello.alpn_protocols();
	assert_eq!(alpn, vec![b"h2".as_slice(), b"http/1.1".as_slice()]);
}

#[test]
fn supported_versions() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	let versions = hello.supported_versions();
	assert_eq!(versions, vec![0x0304, 0x0303]);
}

#[test]
fn supported_groups() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	assert_eq!(hello.supported_groups(), vec![0x001d, 0x0017]);
}

#[test]
fn signature_algorithms() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	assert_eq!(hello.signature_algorithms(), vec![0x0403, 0x0804]);
}

#[test]
fn key_share_groups() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	assert_eq!(hello.key_share_groups(), vec![0x001d]);
}

#[test]
fn renegotiation_info() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	assert!(hello.has_renegotiation_info());
}

#[test]
fn no_renegotiation_info() {
	let data = helpers::minimal_raw();
	let hello = parse(&data).unwrap();
	assert!(!hello.has_renegotiation_info());
}

#[test]
fn find_unknown_extension() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	let raw = hello.find_extension(0x0042);
	assert_eq!(raw, Some([0xDE, 0xAD, 0xBE].as_slice()));
}

#[test]
fn find_missing_extension() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	assert!(hello.find_extension(0x9999).is_none());
}

#[test]
fn grease_filtered_from_cipher_suites() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	for &cs in &hello.cipher_suites {
		assert!(
			!is_grease(cs),
			"GREASE value {cs:#06x} leaked into cipher_suites"
		);
	}
	assert!(hello.has_grease);
}

#[test]
fn grease_filtered_from_versions() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	for &v in hello.supported_versions() {
		assert!(
			!is_grease(v),
			"GREASE value {v:#06x} leaked into supported_versions"
		);
	}
}

#[test]
fn grease_filtered_from_key_share() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	for &g in hello.key_share_groups() {
		assert!(
			!is_grease(g),
			"GREASE value {g:#06x} leaked into key_share_groups"
		);
	}
}

#[test]
fn error_empty_payload() {
	let err = parse(&[]).unwrap_err();
	assert_eq!(err, Error::BufferTooShort { need: 1, have: 0 });
}

#[test]
fn error_not_client_hello() {
	// handshake type 0x02 = ServerHello
	let mut data = helpers::minimal_raw();
	data[0] = 0x02;
	let err = parse(&data).unwrap_err();
	assert_eq!(err, Error::NotClientHello(0x02));
}

#[test]
fn error_not_handshake_record() {
	// content type 0x17 = ApplicationData
	let raw = helpers::minimal_raw();
	let mut record = helpers::wrap_record(&raw);
	record[0] = 0x17;
	let err = parse_from_record(&record).unwrap_err();
	assert_eq!(err, Error::NotHandshakeRecord(0x17));
}

#[test]
fn error_truncated_record() {
	let err = parse_from_record(&[0x16, 0x03]).unwrap_err();
	assert_eq!(err, Error::BufferTooShort { need: 5, have: 2 });
}

#[test]
fn error_truncated_handshake_body() {
	// valid header but body length exceeds available data
	let data = [0x01, 0x00, 0x00, 0xFF, 0x03, 0x03];
	let err = parse(&data).unwrap_err();
	assert!(matches!(err, Error::Truncated { .. }));
}

#[test]
fn empty_session_id() {
	let data = helpers::minimal_raw();
	let hello = parse(&data).unwrap();
	assert!(hello.session_id.is_empty());
}

#[test]
fn full_session_id() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	assert_eq!(hello.session_id.len(), 32);
	assert_eq!(hello.session_id, &[0xCD; 32]);
}

#[test]
fn psk_exchange_modes() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	let modes: &[u8] = hello
		.extensions
		.iter()
		.find_map(|ext| match ext {
			Extension::PskExchangeModes(m) => Some(*m),
			_ => None,
		})
		.unwrap_or_default();
	assert_eq!(modes, [0x01]);
}

#[test]
fn extension_count() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	// SNI + ALPN + SupportedVersions + SupportedGroups + SignatureAlgorithms
	// + KeyShare + PSK + RenegotiationInfo + Unknown(0x0042)
	assert_eq!(hello.extensions.len(), 9);
}

#[test]
fn find_renegotiation_info_raw() {
	let data = helpers::full_raw();
	let hello = parse(&data).unwrap();
	let raw = hello.find_extension(0xFF01);
	// After parsing, RenegotiationInfo stores the renegotiated_connection
	// bytes (with the length prefix stripped), which is empty here.
	assert_eq!(raw, Some([].as_slice()));
}

/* tests/parse.rs */
#![allow(missing_docs)]

mod helpers;

use clienthello::{Error, Extension, is_grease, parse, parse_from_record};

// Happy path

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

// Error path

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

// Happy path: structural edge cases

#[test]
fn empty_extensions_section() {
	// Extensions section present but with length = 0.
	let data = helpers::raw_with_extensions(&[]);
	let hello = parse(&data).unwrap();
	assert!(hello.extensions.is_empty());
}

#[test]
fn trailing_byte_after_compression_no_extensions() {
	// Body has 1 trailing byte after compression (remaining < 2),
	// so the parser skips extension parsing.
	let mut body = helpers::minimal_body();
	body.push(0xFF); // 1 trailing byte
	let data = helpers::wrap_handshake(&body);
	let hello = parse(&data).unwrap();
	assert!(hello.extensions.is_empty());
}

#[test]
fn only_unknown_extensions() {
	let mut exts = helpers::build_ext(0x0042, &[0x01, 0x02]);
	exts.extend_from_slice(&helpers::build_ext(0x0043, &[0x03]));
	let data = helpers::raw_with_extensions(&exts);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.extensions.len(), 2);
	assert!(matches!(
		&hello.extensions[0],
		Extension::Unknown { type_id: 0x0042, data } if *data == [0x01, 0x02]
	));
	assert!(matches!(
		&hello.extensions[1],
		Extension::Unknown { type_id: 0x0043, data } if *data == [0x03]
	));
}

#[test]
fn multiple_compression_methods() {
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]); // version
	body.extend_from_slice(&[0u8; 32]); // random
	body.push(0x00); // no session ID
	body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
	body.push(0x03); // compression methods length = 3
	body.extend_from_slice(&[0x00, 0x01, 0x02]); // three methods
	let data = helpers::wrap_handshake(&body);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.compression_methods, &[0x00, 0x01, 0x02]);
}

#[test]
fn grease_extension_type_skipped() {
	// An extension with a GREASE type_id is silently skipped.
	let mut exts = helpers::build_ext(0x0A0A, &[0x01, 0x02]); // GREASE type
	exts.extend_from_slice(&helpers::build_ext(0x0042, &[0xAA]));
	let data = helpers::raw_with_extensions(&exts);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.extensions.len(), 1); // only 0x0042
	assert!(hello.has_grease);
}

#[test]
fn grease_only_from_extension_type() {
	// GREASE appears only as an extension type_id, not in cipher suites.
	// has_grease should still be true.
	let exts = helpers::build_ext(0x2A2A, &[0x00]); // GREASE extension type
	let data = helpers::raw_with_extensions(&exts);
	let hello = parse(&data).unwrap();
	assert!(hello.has_grease);
	assert!(hello.extensions.is_empty()); // GREASE ext is skipped
	// cipher_suites contain no GREASE (minimal body has 0x1301 only)
	assert_eq!(hello.cipher_suites, vec![0x1301]);
}

#[test]
fn grease_filtered_from_supported_groups() {
	let body = helpers::build_u16_list_body(&[0x2A2A, 0x001d, 0x0017]);
	let ext = helpers::build_ext(0x000A, &body);
	let data = helpers::raw_with_extensions(&ext);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.supported_groups(), &[0x001d, 0x0017]);
	assert!(hello.has_grease);
}

#[test]
fn grease_filtered_from_sig_algs() {
	let mut sa_body = Vec::new();
	helpers::push_u16(&mut sa_body, 6); // 3 * 2 bytes
	helpers::push_u16(&mut sa_body, 0x0A0A); // GREASE
	helpers::push_u16(&mut sa_body, 0x0403);
	helpers::push_u16(&mut sa_body, 0x0804);
	let ext = helpers::build_ext(0x000D, &sa_body);
	let data = helpers::raw_with_extensions(&ext);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.signature_algorithms(), &[0x0403, 0x0804]);
	assert!(hello.has_grease);
}

// Happy path: SNI edge cases

#[test]
fn sni_non_dns_type_returns_none() {
	// SNI entry with name_type = 1 (not DNS hostname).
	// server_name() only returns type 0x00 entries.
	let sni_body = helpers::build_sni_body(&[(0x01, b"example.com")]);
	let ext = helpers::build_ext(0x0000, &sni_body);
	let data = helpers::raw_with_extensions(&ext);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.server_name(), None);
	// But the extension IS parsed
	assert_eq!(hello.extensions.len(), 1);
}

#[test]
fn sni_mixed_types_returns_first_dns() {
	// Non-DNS entry first, then DNS entry. server_name() finds the DNS one.
	let sni_body = helpers::build_sni_body(&[
		(0x01, b"wrong.com"),   // non-DNS
		(0x00, b"correct.com"), // DNS hostname
	]);
	let ext = helpers::build_ext(0x0000, &sni_body);
	let data = helpers::raw_with_extensions(&ext);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.server_name(), Some("correct.com"));
}

#[test]
fn sni_invalid_utf8_returns_none() {
	// DNS type but name bytes are invalid UTF-8.
	// from_utf8().ok() returns None.
	let sni_body = helpers::build_sni_body(&[(0x00, &[0xFF, 0xFE, 0xFD])]);
	let ext = helpers::build_ext(0x0000, &sni_body);
	let data = helpers::raw_with_extensions(&ext);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.server_name(), None);
}

// Happy path: extension accessor edge cases

#[test]
fn single_alpn_protocol() {
	let alpn_body = helpers::build_alpn_body(&[b"h3"]);
	let ext = helpers::build_ext(0x0010, &alpn_body);
	let data = helpers::raw_with_extensions(&ext);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.alpn_protocols(), &[b"h3".as_slice()]);
}

#[test]
fn supported_versions_single() {
	let sv_body = helpers::build_supported_versions_body(&[0x0304]);
	let ext = helpers::build_ext(0x002B, &sv_body);
	let data = helpers::raw_with_extensions(&ext);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.supported_versions(), &[0x0304]);
}

#[test]
fn key_share_empty_list() {
	let ks_body = helpers::build_key_share_body(&[]);
	let ext = helpers::build_ext(0x0033, &ks_body);
	let data = helpers::raw_with_extensions(&ext);
	let hello = parse(&data).unwrap();
	assert!(hello.key_share_groups().is_empty());
}

#[test]
fn find_extension_psk_modes_by_type_id() {
	// Build PSK modes extension with modes [0x00, 0x01].
	let psk_body = [0x02, 0x00, 0x01]; // length=2, modes=[0x00, 0x01]
	let ext = helpers::build_ext(0x002D, &psk_body);
	let data = helpers::raw_with_extensions(&ext);
	let hello = parse(&data).unwrap();
	assert_eq!(hello.find_extension(0x002D), Some([0x00, 0x01].as_slice()));
}

#[test]
fn accessors_default_without_extensions() {
	// On a minimal ClientHello with no extensions, all accessors
	// return their default (empty) values.
	let data = helpers::minimal_raw();
	let hello = parse(&data).unwrap();
	assert_eq!(hello.server_name(), None);
	assert!(hello.alpn_protocols().is_empty());
	assert!(hello.supported_versions().is_empty());
	assert!(hello.supported_groups().is_empty());
	assert!(hello.signature_algorithms().is_empty());
	assert!(hello.key_share_groups().is_empty());
	assert!(!hello.has_renegotiation_info());
	assert!(hello.find_extension(0x0042).is_none());
}

// Error path: handshake header

#[test]
fn error_parse_only_type_byte() {
	// Only the handshake type byte (0x01), no room for the 3-byte length.
	let err = parse(&[0x01]).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "handshake length"
		}
	);
}

#[test]
fn error_not_client_hello_server_hello() {
	let mut data = helpers::minimal_raw();
	data[0] = 0x02; // ServerHello
	assert_eq!(parse(&data).unwrap_err(), Error::NotClientHello(0x02));
}

#[test]
fn error_not_client_hello_certificate() {
	let mut data = helpers::minimal_raw();
	data[0] = 0x0B; // Certificate
	assert_eq!(parse(&data).unwrap_err(), Error::NotClientHello(0x0B));
}

#[test]
fn error_not_client_hello_zero() {
	let mut data = helpers::minimal_raw();
	data[0] = 0x00; // HelloRequest
	assert_eq!(parse(&data).unwrap_err(), Error::NotClientHello(0x00));
}

#[test]
fn error_not_client_hello_0xff() {
	let mut data = helpers::minimal_raw();
	data[0] = 0xFF;
	assert_eq!(parse(&data).unwrap_err(), Error::NotClientHello(0xFF));
}

// Error path: body field truncation

#[test]
fn error_truncated_legacy_version() {
	// Body is 1 byte — not enough for the u16 legacy_version.
	let data = helpers::wrap_handshake(&[0x03]);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "legacy version"
		}
	);
}

#[test]
fn error_truncated_random() {
	// Body has version but only 16 of 32 random bytes.
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0u8; 16]); // only 16 bytes
	let data = helpers::wrap_handshake(&body);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "client random"
		}
	);
}

#[test]
fn error_truncated_session_id_length() {
	// Body has version + random, then ends — no session ID length byte.
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0u8; 32]);
	let data = helpers::wrap_handshake(&body);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "session ID length"
		}
	);
}

#[test]
fn error_truncated_session_id() {
	// Session ID length says 32 but only 10 bytes follow.
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0u8; 32]);
	body.push(0x20); // session ID length = 32
	body.extend_from_slice(&[0u8; 10]); // only 10 bytes
	let data = helpers::wrap_handshake(&body);
	let err = parse(&data).unwrap_err();
	assert_eq!(err, Error::Truncated { field: "session ID" });
}

#[test]
fn error_truncated_cipher_suites_length() {
	// After session_id, no room for cipher suites u16 length.
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0u8; 32]);
	body.push(0x00); // empty session ID
	let data = helpers::wrap_handshake(&body);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "cipher suites length"
		}
	);
}

#[test]
fn error_truncated_cipher_suites_data() {
	// Cipher suites length says 4 but only 2 bytes follow.
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0u8; 32]);
	body.push(0x00); // no session ID
	helpers::push_u16(&mut body, 4); // cipher suites length = 4
	body.extend_from_slice(&[0x13, 0x01]); // only 2 bytes
	let data = helpers::wrap_handshake(&body);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "cipher suites data"
		}
	);
}

#[test]
fn error_truncated_compression_length() {
	// After cipher suites, no room for compression methods length byte.
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0u8; 32]);
	body.push(0x00); // no session ID
	helpers::push_u16(&mut body, 2); // cipher suites length = 2
	body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
	// no compression methods length
	let data = helpers::wrap_handshake(&body);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "compression methods length"
		}
	);
}

#[test]
fn error_truncated_compression_data() {
	// Compression methods length says 3 but only 1 byte follows.
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0u8; 32]);
	body.push(0x00); // no session ID
	helpers::push_u16(&mut body, 2);
	body.extend_from_slice(&[0x13, 0x01]);
	body.push(0x03); // compression length = 3
	body.push(0x00); // only 1 byte
	let data = helpers::wrap_handshake(&body);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "compression methods"
		}
	);
}

// Error path: odd-length u16 lists

#[test]
fn error_odd_cipher_suites() {
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0u8; 32]);
	body.push(0x00);
	helpers::push_u16(&mut body, 3); // odd length!
	body.extend_from_slice(&[0x13, 0x01, 0x00]); // 3 bytes
	body.extend_from_slice(&[0x01, 0x00]); // compression
	let data = helpers::wrap_handshake(&body);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "cipher suites (odd length)"
		}
	);
}

#[test]
fn error_odd_supported_groups() {
	// supported groups (0x000a) uses parse_u16_list_filtered
	let mut group_body = Vec::new();
	helpers::push_u16(&mut group_body, 3); // odd length!
	group_body.extend_from_slice(&[0x00, 0x1d, 0x00]); // 3 bytes
	let ext = helpers::build_ext(0x000A, &group_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "u16 list (odd length)"
		}
	);
}

#[test]
fn error_odd_signature_algorithms() {
	let mut sa_body = Vec::new();
	helpers::push_u16(&mut sa_body, 3); // odd length!
	sa_body.extend_from_slice(&[0x04, 0x03, 0x00]); // 3 bytes
	let ext = helpers::build_ext(0x000D, &sa_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "signature algorithms (odd length)"
		}
	);
}

#[test]
fn error_odd_supported_versions() {
	// supported versions uses a u8 length prefix
	let sv_body = [0x03, 0x03, 0x04, 0x00]; // length=3 (odd!), then 3 bytes
	let ext = helpers::build_ext(0x002B, &sv_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "supported versions (odd length)"
		}
	);
}

// Error path: extensions truncation

#[test]
fn error_truncated_extensions_data() {
	// Extensions length (100) exceeds available data (10 bytes).
	let mut body = helpers::minimal_body();
	helpers::push_u16(&mut body, 100); // extensions length = 100
	body.extend_from_slice(&[0x00; 10]); // only 10 bytes
	let data = helpers::wrap_handshake(&body);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "extensions data"
		}
	);
}

#[test]
fn error_truncated_extension_body() {
	// Extension header says body is 10 bytes but only 5 follow.
	let mut ext_data = Vec::new();
	helpers::push_u16(&mut ext_data, 0x0042); // type
	helpers::push_u16(&mut ext_data, 10); // length = 10
	ext_data.extend_from_slice(&[0x00; 5]); // only 5 bytes
	let data = helpers::raw_with_extensions(&ext_data);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "extension body"
		}
	);
}

#[test]
fn error_truncated_sni_list() {
	// SNI extension with list_length exceeding available data.
	let sni_body = [0x00, 0x20]; // list_len=32, but no list data
	let ext = helpers::build_ext(0x0000, &sni_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "SNI list data"
		}
	);
}

#[test]
fn error_truncated_sni_name() {
	// SNI list is well-formed in length, but an entry's name_len
	// exceeds the available bytes inside the list.
	let mut list = Vec::new();
	list.push(0x00); // name_type = DNS
	helpers::push_u16(&mut list, 100); // name_len = 100, way too large

	let mut sni_body = Vec::new();
	helpers::push_u16(&mut sni_body, list.len() as u16); // list_len = 3
	sni_body.extend_from_slice(&list);

	let ext = helpers::build_ext(0x0000, &sni_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(err, Error::Truncated { field: "SNI name" });
}

#[test]
fn error_truncated_alpn_list() {
	// ALPN extension with list_length exceeding available data.
	let alpn_body = [0x00, 0x20]; // list_len=32, no data
	let ext = helpers::build_ext(0x0010, &alpn_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "ALPN list data"
		}
	);
}

#[test]
fn error_truncated_alpn_protocol() {
	// ALPN list is well-formed in length, but a protocol's length
	// exceeds available bytes inside the list.
	let list: Vec<u8> = vec![50, 0x68, 0x32]; // proto_len=50, "h2" only 2 bytes
	let mut alpn_body = Vec::new();
	helpers::push_u16(&mut alpn_body, list.len() as u16); // list_len = 3
	alpn_body.extend_from_slice(&list);

	let ext = helpers::build_ext(0x0010, &alpn_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "ALPN protocol"
		}
	);
}

#[test]
fn error_truncated_key_share_key() {
	// Key share: valid list structure, but key_len exceeds available.
	let mut ks_body = Vec::new();
	helpers::push_u16(&mut ks_body, 6); // list_len = 6
	helpers::push_u16(&mut ks_body, 0x001d); // group
	helpers::push_u16(&mut ks_body, 32); // key_len = 32 (but only 2 bytes remain)
	ks_body.extend_from_slice(&[0x00; 2]); // 2 bytes of key data
	let ext = helpers::build_ext(0x0033, &ks_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "key share key data"
		}
	);
}

#[test]
fn error_truncated_renegotiation_info() {
	// Renegotiation info length exceeds available data.
	let ri_body = [0x10]; // info_len=16, no data
	let ext = helpers::build_ext(0xFF01, &ri_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "renegotiation info data"
		}
	);
}

#[test]
fn error_truncated_psk_modes() {
	// PSK modes length exceeds available data.
	let psk_body = [0x10]; // modes_len=16, no data
	let ext = helpers::build_ext(0x002D, &psk_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "PSK modes data"
		}
	);
}

#[test]
fn error_truncated_supported_versions_data() {
	// supported versions list_len exceeds available data.
	let sv_body = [0x10]; // list_len=16, no data
	let ext = helpers::build_ext(0x002B, &sv_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "supported versions data"
		}
	);
}

#[test]
fn error_truncated_key_share_list() {
	// Key share list_len exceeds available data.
	let ks_body = [0x00, 0x20]; // list_len=32, no data
	let ext = helpers::build_ext(0x0033, &ks_body);
	let data = helpers::raw_with_extensions(&ext);
	let err = parse(&data).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "key share list data"
		}
	);
}

// Error path: record layer

#[test]
fn error_record_payload_truncated() {
	// Record header says payload is 100 bytes but only 10 follow.
	let mut rec = vec![0x16, 0x03, 0x01];
	helpers::push_u16(&mut rec, 100);
	rec.extend_from_slice(&[0x00; 10]);
	let err = parse_from_record(&rec).unwrap_err();
	assert_eq!(
		err,
		Error::Truncated {
			field: "record payload"
		}
	);
}

#[test]
fn error_record_empty_payload() {
	// Record with length = 0. Inner parse() sees empty input.
	let rec = vec![0x16, 0x03, 0x01, 0x00, 0x00];
	let err = parse_from_record(&rec).unwrap_err();
	assert_eq!(err, Error::BufferTooShort { need: 1, have: 0 });
}

#[test]
fn error_record_content_type_alert() {
	let raw = helpers::minimal_raw();
	let mut rec = helpers::wrap_record(&raw);
	rec[0] = 0x15; // Alert
	assert_eq!(
		parse_from_record(&rec).unwrap_err(),
		Error::NotHandshakeRecord(0x15)
	);
}

#[test]
fn error_record_content_type_ccs() {
	let raw = helpers::minimal_raw();
	let mut rec = helpers::wrap_record(&raw);
	rec[0] = 0x14; // ChangeCipherSpec
	assert_eq!(
		parse_from_record(&rec).unwrap_err(),
		Error::NotHandshakeRecord(0x14)
	);
}

#[test]
fn error_record_content_type_0xff() {
	let raw = helpers::minimal_raw();
	let mut rec = helpers::wrap_record(&raw);
	rec[0] = 0xFF;
	assert_eq!(
		parse_from_record(&rec).unwrap_err(),
		Error::NotHandshakeRecord(0xFF)
	);
}

#[test]
fn error_record_single_byte() {
	// Only 1 byte — not enough for the 5-byte record header.
	let err = parse_from_record(&[0x16]).unwrap_err();
	assert_eq!(err, Error::BufferTooShort { need: 5, have: 1 });
}

#[test]
fn error_record_three_bytes() {
	let err = parse_from_record(&[0x16, 0x03, 0x01]).unwrap_err();
	assert_eq!(err, Error::BufferTooShort { need: 5, have: 3 });
}

#[test]
fn error_record_four_bytes() {
	let err = parse_from_record(&[0x16, 0x03, 0x01, 0x00]).unwrap_err();
	assert_eq!(err, Error::BufferTooShort { need: 5, have: 4 });
}

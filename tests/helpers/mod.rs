/* tests/helpers/mod.rs */

pub(crate) fn minimal_raw() -> Vec<u8> {
	wrap_handshake(&minimal_body())
}

/// Build a minimal ClientHello body (no handshake header).
pub(crate) fn minimal_body() -> Vec<u8> {
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]); // legacy version
	body.extend_from_slice(&[0u8; 32]); // random
	body.push(0x00); // session ID length
	body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
	body.extend_from_slice(&[0x01, 0x00]); // compression
	body
}

/// Wrap a ClientHello body in a handshake header (type 0x01 + 3-byte length).
pub(crate) fn wrap_handshake(body: &[u8]) -> Vec<u8> {
	let mut msg = vec![0x01]; // handshake type
	let len = body.len() as u32;
	msg.push((len >> 16) as u8);
	msg.push((len >> 8) as u8);
	msg.push(len as u8);
	msg.extend_from_slice(body);
	msg
}

/// Wrap a raw handshake message in a TLS record layer.
pub(crate) fn wrap_record(handshake: &[u8]) -> Vec<u8> {
	let mut rec = vec![0x16, 0x03, 0x01]; // content type + version
	let len = handshake.len() as u16;
	rec.push((len >> 8) as u8);
	rec.push(len as u8);
	rec.extend_from_slice(handshake);
	rec
}

/// Build a raw handshake message from a minimal body with custom extensions.
pub(crate) fn raw_with_extensions(ext_bytes: &[u8]) -> Vec<u8> {
	let mut body = minimal_body();
	push_u16(&mut body, ext_bytes.len() as u16);
	body.extend_from_slice(ext_bytes);
	wrap_handshake(&body)
}

/// Build a single TLS extension: type_id (u16) + length (u16) + data.
pub(crate) fn build_ext(type_id: u16, data: &[u8]) -> Vec<u8> {
	let mut ext = Vec::new();
	push_u16(&mut ext, type_id);
	push_u16(&mut ext, data.len() as u16);
	ext.extend_from_slice(data);
	ext
}

/// Build SNI extension body from (name_type, name) pairs.
pub(crate) fn build_sni_body(entries: &[(u8, &[u8])]) -> Vec<u8> {
	let mut list = Vec::new();
	for &(name_type, name) in entries {
		list.push(name_type);
		push_u16(&mut list, name.len() as u16);
		list.extend_from_slice(name);
	}
	let mut body = Vec::new();
	push_u16(&mut body, list.len() as u16);
	body.extend_from_slice(&list);
	body
}

/// Build ALPN extension body from protocol byte slices.
pub(crate) fn build_alpn_body(protocols: &[&[u8]]) -> Vec<u8> {
	let mut list = Vec::new();
	for proto in protocols {
		list.push(proto.len() as u8);
		list.extend_from_slice(proto);
	}
	let mut body = Vec::new();
	push_u16(&mut body, list.len() as u16);
	body.extend_from_slice(&list);
	body
}

/// Build supported versions extension body (u8 length prefix per RFC 8446).
pub(crate) fn build_supported_versions_body(versions: &[u16]) -> Vec<u8> {
	let mut body = Vec::new();
	body.push((versions.len() * 2) as u8);
	for &v in versions {
		push_u16(&mut body, v);
	}
	body
}

/// Build key share extension body from (group, key_data) pairs.
pub(crate) fn build_key_share_body(entries: &[(u16, &[u8])]) -> Vec<u8> {
	let mut list = Vec::new();
	for &(group, key) in entries {
		push_u16(&mut list, group);
		push_u16(&mut list, key.len() as u16);
		list.extend_from_slice(key);
	}
	let mut body = Vec::new();
	push_u16(&mut body, list.len() as u16);
	body.extend_from_slice(&list);
	body
}

/// Build a u16-list extension body with a u16 length prefix.
pub(crate) fn build_u16_list_body(values: &[u16]) -> Vec<u8> {
	let mut body = Vec::new();
	push_u16(&mut body, (values.len() * 2) as u16);
	for &v in values {
		push_u16(&mut body, v);
	}
	body
}

/// Build a raw ClientHello with common extensions.
pub(crate) fn full_raw() -> Vec<u8> {
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]); // legacy version
	body.extend_from_slice(&[0xAB; 32]); // random
	// session ID (32 bytes)
	body.push(0x20);
	body.extend_from_slice(&[0xCD; 32]);
	// cipher suites: GREASE + TLS_AES_128_GCM + TLS_AES_256_GCM + TLS_CHACHA20
	body.extend_from_slice(&[0x00, 0x08]);
	body.extend_from_slice(&[0x0A, 0x0A]); // GREASE
	body.extend_from_slice(&[0x13, 0x01]);
	body.extend_from_slice(&[0x13, 0x02]);
	body.extend_from_slice(&[0x13, 0x03]);
	// compression
	body.extend_from_slice(&[0x01, 0x00]);

	let extensions = build_extensions();
	let ext_len = extensions.len() as u16;
	body.push((ext_len >> 8) as u8);
	body.push(ext_len as u8);
	body.extend_from_slice(&extensions);

	let mut msg = vec![0x01];
	let len = body.len() as u32;
	msg.push((len >> 16) as u8);
	msg.push((len >> 8) as u8);
	msg.push(len as u8);
	msg.extend_from_slice(&body);
	msg
}

fn build_extensions() -> Vec<u8> {
	let mut exts = Vec::new();

	// SNI: example.com
	let host = b"example.com";
	let sni_list_len = 1 + 2 + host.len(); // type + name_len + name
	let sni_ext_len = 2 + sni_list_len; // list_len field + list
	push_ext_header(&mut exts, 0x0000, sni_ext_len);
	push_u16(&mut exts, sni_list_len as u16);
	exts.push(0x00); // host_name type
	push_u16(&mut exts, host.len() as u16);
	exts.extend_from_slice(host);

	// ALPN: h2, http/1.1
	let proto1 = b"h2";
	let proto2 = b"http/1.1";
	let alpn_list_len = 1 + proto1.len() + 1 + proto2.len();
	let alpn_ext_len = 2 + alpn_list_len;
	push_ext_header(&mut exts, 0x0010, alpn_ext_len);
	push_u16(&mut exts, alpn_list_len as u16);
	exts.push(proto1.len() as u8);
	exts.extend_from_slice(proto1);
	exts.push(proto2.len() as u8);
	exts.extend_from_slice(proto2);

	// Supported Versions: GREASE + TLS 1.3 + TLS 1.2
	let sv_list_len = 6; // 3 * 2 bytes
	push_ext_header(&mut exts, 0x002b, 1 + sv_list_len);
	exts.push(sv_list_len as u8);
	push_u16(&mut exts, 0x3A3A); // GREASE
	push_u16(&mut exts, 0x0304); // TLS 1.3
	push_u16(&mut exts, 0x0303); // TLS 1.2

	// Supported Groups: x25519 + secp256r1
	push_ext_header(&mut exts, 0x000a, 2 + 4);
	push_u16(&mut exts, 4);
	push_u16(&mut exts, 0x001d); // x25519
	push_u16(&mut exts, 0x0017); // secp256r1

	// Signature Algorithms: ecdsa_secp256r1_sha256 + rsa_pss_rsae_sha256
	push_ext_header(&mut exts, 0x000d, 2 + 4);
	push_u16(&mut exts, 4);
	push_u16(&mut exts, 0x0403);
	push_u16(&mut exts, 0x0804);

	// Key Share: GREASE + x25519 (dummy 32-byte key)
	let ks_entry_grease = 2 + 2 + 1; // group + len + 1-byte key
	let ks_entry_real = 2 + 2 + 32; // group + len + 32-byte key
	let ks_list_len = ks_entry_grease + ks_entry_real;
	push_ext_header(&mut exts, 0x0033, 2 + ks_list_len);
	push_u16(&mut exts, ks_list_len as u16);
	push_u16(&mut exts, 0x1A1A); // GREASE group
	push_u16(&mut exts, 1);
	exts.push(0x00);
	push_u16(&mut exts, 0x001d); // x25519
	push_u16(&mut exts, 32);
	exts.extend_from_slice(&[0xEE; 32]);

	// PSK Exchange Modes: psk_dhe_ke
	push_ext_header(&mut exts, 0x002d, 2);
	exts.push(0x01); // modes length
	exts.push(0x01); // psk_dhe_ke

	// Renegotiation Info: empty
	push_ext_header(&mut exts, 0xff01, 1);
	exts.push(0x00);

	// Unknown extension 0x0042
	push_ext_header(&mut exts, 0x0042, 3);
	exts.extend_from_slice(&[0xDE, 0xAD, 0xBE]);

	exts
}

fn push_ext_header(buf: &mut Vec<u8>, type_id: u16, data_len: usize) {
	push_u16(buf, type_id);
	push_u16(buf, data_len as u16);
}

pub(crate) fn push_u16(buf: &mut Vec<u8>, val: u16) {
	buf.push((val >> 8) as u8);
	buf.push(val as u8);
}

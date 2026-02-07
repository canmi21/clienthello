/* tests/helpers/mod.rs */

pub(crate) fn minimal_raw() -> Vec<u8> {
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]); // legacy version
	body.extend_from_slice(&[0u8; 32]); // random
	body.push(0x00); // session ID length
	body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
	body.extend_from_slice(&[0x01, 0x00]); // compression

	let mut msg = vec![0x01]; // handshake type
	let len = body.len() as u32;
	msg.push((len >> 16) as u8);
	msg.push((len >> 8) as u8);
	msg.push(len as u8);
	msg.extend_from_slice(&body);
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

fn push_u16(buf: &mut Vec<u8>, val: u16) {
	buf.push((val >> 8) as u8);
	buf.push(val as u8);
}

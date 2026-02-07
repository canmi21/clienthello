/* examples/parse_record.rs */
#![allow(missing_docs)]

fn main() {
	let record = build_sample_record();

	match clienthello::parse_from_record(&record) {
		Ok(hello) => {
			println!("Legacy version: {:#06x}", hello.legacy_version);
			println!("Random: {:02x?}", hello.random);
			println!(
				"Session ID ({} bytes): {:02x?}",
				hello.session_id.len(),
				hello.session_id
			);
			println!(
				"Cipher suites: {:?}",
				hello
					.cipher_suites
					.iter()
					.map(|cs| format!("{cs:#06x}"))
					.collect::<Vec<_>>()
			);
			println!("Has GREASE: {}", hello.has_grease);

			if let Some(sni) = hello.server_name() {
				println!("SNI: {sni}");
			}

			let alpn = hello.alpn_protocols();
			if !alpn.is_empty() {
				let names: Vec<&str> = alpn
					.iter()
					.filter_map(|p| core::str::from_utf8(p).ok())
					.collect();
				println!("ALPN: {names:?}");
			}

			let versions = hello.supported_versions();
			if !versions.is_empty() {
				println!(
					"Supported versions: {:?}",
					versions
						.iter()
						.map(|v| format!("{v:#06x}"))
						.collect::<Vec<_>>()
				);
			}

			let groups = hello.supported_groups();
			if !groups.is_empty() {
				println!(
					"Supported groups: {:?}",
					groups
						.iter()
						.map(|g| format!("{g:#06x}"))
						.collect::<Vec<_>>()
				);
			}

			let sig_algs = hello.signature_algorithms();
			if !sig_algs.is_empty() {
				println!(
					"Signature algorithms: {:?}",
					sig_algs
						.iter()
						.map(|a| format!("{a:#06x}"))
						.collect::<Vec<_>>()
				);
			}

			let ks = hello.key_share_groups();
			if !ks.is_empty() {
				println!(
					"Key share groups: {:?}",
					ks.iter().map(|g| format!("{g:#06x}")).collect::<Vec<_>>()
				);
			}

			println!("Renegotiation info: {}", hello.has_renegotiation_info());
			println!("Extensions count: {}", hello.extensions.len());
		}
		Err(e) => eprintln!("Parse error: {e}"),
	}
}

fn build_sample_record() -> Vec<u8> {
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0x42; 32]);
	body.push(0x00);
	body.extend_from_slice(&[0x00, 0x06]);
	body.extend_from_slice(&[0x0A, 0x0A]); // GREASE
	body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
	body.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384
	body.extend_from_slice(&[0x01, 0x00]);

	let mut exts = Vec::new();

	// SNI
	let host = b"www.example.com";
	let sni_list = 1 + 2 + host.len();
	push_u16(&mut exts, 0x0000);
	push_u16(&mut exts, (2 + sni_list) as u16);
	push_u16(&mut exts, sni_list as u16);
	exts.push(0x00);
	push_u16(&mut exts, host.len() as u16);
	exts.extend_from_slice(host);

	// ALPN
	push_u16(&mut exts, 0x0010);
	push_u16(&mut exts, 14);
	push_u16(&mut exts, 12);
	exts.push(2);
	exts.extend_from_slice(b"h2");
	exts.push(8);
	exts.extend_from_slice(b"http/1.1");

	// Supported Versions
	push_u16(&mut exts, 0x002b);
	push_u16(&mut exts, 3);
	exts.push(2);
	push_u16(&mut exts, 0x0304);

	push_u16(&mut body, exts.len() as u16);
	body.extend_from_slice(&exts);

	let mut hs = vec![0x01];
	let len = body.len() as u32;
	hs.push((len >> 16) as u8);
	hs.push((len >> 8) as u8);
	hs.push(len as u8);
	hs.extend_from_slice(&body);

	let mut record = vec![0x16, 0x03, 0x01];
	push_u16(&mut record, hs.len() as u16);
	record.extend_from_slice(&hs);
	record
}

fn push_u16(buf: &mut Vec<u8>, val: u16) {
	buf.push((val >> 8) as u8);
	buf.push(val as u8);
}

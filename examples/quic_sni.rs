/* examples/quic_sni.rs */
#![allow(missing_docs)]

fn main() {
	let raw = build_quic_client_hello();

	match clienthello::parse(&raw) {
		Ok(hello) => match hello.server_name() {
			Some(name) => println!("SNI: {name}"),
			None => println!("No SNI present"),
		},
		Err(e) => eprintln!("Parse error: {e}"),
	}
}

fn build_quic_client_hello() -> Vec<u8> {
	let mut body = Vec::new();
	body.extend_from_slice(&[0x03, 0x03]);
	body.extend_from_slice(&[0x00; 32]);
	body.push(0x00);
	body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
	body.extend_from_slice(&[0x01, 0x00]);

	// SNI extension
	let mut exts = Vec::new();
	let host = b"quic.example.org";
	let sni_list = 1 + 2 + host.len();
	push_u16(&mut exts, 0x0000);
	push_u16(&mut exts, (2 + sni_list) as u16);
	push_u16(&mut exts, sni_list as u16);
	exts.push(0x00);
	push_u16(&mut exts, host.len() as u16);
	exts.extend_from_slice(host);

	push_u16(&mut body, exts.len() as u16);
	body.extend_from_slice(&exts);

	let mut msg = vec![0x01];
	let len = body.len() as u32;
	msg.push((len >> 16) as u8);
	msg.push((len >> 8) as u8);
	msg.push(len as u8);
	msg.extend_from_slice(&body);
	msg
}

fn push_u16(buf: &mut Vec<u8>, val: u16) {
	buf.push((val >> 8) as u8);
	buf.push(val as u8);
}

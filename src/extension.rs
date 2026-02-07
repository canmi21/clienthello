/* src/extension.rs */

use alloc::vec::Vec;

use crate::Error;
use crate::grease::is_grease;
use crate::reader::Reader;

/// A parsed TLS extension from the ClientHello message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Extension<'a> {
	/// Server Name Indication (type `0x0000`).
	ServerName(Vec<ServerName<'a>>),
	/// Application-Layer Protocol Negotiation (type `0x0010`).
	Alpn(Vec<&'a [u8]>),
	/// Supported Versions (type `0x002b`), GREASE values excluded.
	SupportedVersions(Vec<u16>),
	/// Supported Groups / Named Curves (type `0x000a`), GREASE values excluded.
	SupportedGroups(Vec<u16>),
	/// Signature Algorithms (type `0x000d`).
	SignatureAlgorithms(Vec<u16>),
	/// Key Share entry groups (type `0x0033`), GREASE values excluded.
	KeyShareGroups(Vec<u16>),
	/// PSK Key Exchange Modes (type `0x002d`).
	PskExchangeModes(Vec<u8>),
	/// Renegotiation Info (type `0xff01`).
	RenegotiationInfo(&'a [u8]),
	/// Unknown or unhandled extension preserved as raw bytes.
	Unknown {
		/// TLS extension type identifier.
		type_id: u16,
		/// Raw extension data.
		data: &'a [u8],
	},
}

/// A single entry in the SNI (Server Name Indication) list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerName<'a> {
	/// Name type byte; `0x00` indicates a DNS hostname.
	pub name_type: u8,
	/// Raw name bytes.
	pub name: &'a [u8],
}

pub(crate) fn parse_extension<'a>(
	type_id: u16,
	data: &'a [u8],
	has_grease: &mut bool,
) -> Result<Extension<'a>, Error> {
	if is_grease(type_id) {
		*has_grease = true;
		return Ok(Extension::Unknown { type_id, data });
	}
	match type_id {
		0x0000 => parse_sni(data),
		0x000a => parse_groups(data, has_grease),
		0x000d => parse_sig_algs(data),
		0x0010 => parse_alpn(data),
		0x002b => parse_supported_versions(data, has_grease),
		0x002d => parse_psk_modes(data),
		0x0033 => parse_key_share(data, has_grease),
		0xff01 => Ok(Extension::RenegotiationInfo(data)),
		_ => Ok(Extension::Unknown { type_id, data }),
	}
}

fn parse_sni<'a>(data: &'a [u8]) -> Result<Extension<'a>, Error> {
	let mut r = Reader::new(data);
	let list_len = r.read_u16("SNI list length")? as usize;
	let list_data = r.read_bytes(list_len, "SNI list data")?;
	let mut inner = Reader::new(list_data);
	let mut names = Vec::new();
	while inner.remaining() > 0 {
		let name_type = inner.read_u8("SNI name type")?;
		let name_len = inner.read_u16("SNI name length")? as usize;
		let name = inner.read_bytes(name_len, "SNI name")?;
		names.push(ServerName { name_type, name });
	}
	Ok(Extension::ServerName(names))
}

fn parse_groups<'a>(data: &'a [u8], has_grease: &mut bool) -> Result<Extension<'a>, Error> {
	Ok(Extension::SupportedGroups(parse_u16_list_filtered(
		data, has_grease,
	)?))
}

fn parse_sig_algs(data: &[u8]) -> Result<Extension<'_>, Error> {
	let mut r = Reader::new(data);
	let list_len = r.read_u16("signature algorithms length")? as usize;
	let list_data = r.read_bytes(list_len, "signature algorithms data")?;
	let mut inner = Reader::new(list_data);
	let mut algs = Vec::new();
	while inner.remaining() >= 2 {
		algs.push(inner.read_u16("signature algorithm")?);
	}
	Ok(Extension::SignatureAlgorithms(algs))
}

fn parse_alpn<'a>(data: &'a [u8]) -> Result<Extension<'a>, Error> {
	let mut r = Reader::new(data);
	let list_len = r.read_u16("ALPN list length")? as usize;
	let list_data = r.read_bytes(list_len, "ALPN list data")?;
	let mut inner = Reader::new(list_data);
	let mut protocols = Vec::new();
	while inner.remaining() > 0 {
		let proto_len = inner.read_u8("ALPN protocol length")? as usize;
		let proto = inner.read_bytes(proto_len, "ALPN protocol")?;
		protocols.push(proto);
	}
	Ok(Extension::Alpn(protocols))
}

fn parse_supported_versions<'a>(
	data: &'a [u8],
	has_grease: &mut bool,
) -> Result<Extension<'a>, Error> {
	let mut r = Reader::new(data);
	let list_len = r.read_u8("supported versions length")? as usize;
	let list_data = r.read_bytes(list_len, "supported versions data")?;
	let mut inner = Reader::new(list_data);
	let mut versions = Vec::new();
	while inner.remaining() >= 2 {
		let ver = inner.read_u16("supported version")?;
		if is_grease(ver) {
			*has_grease = true;
		} else {
			versions.push(ver);
		}
	}
	Ok(Extension::SupportedVersions(versions))
}

fn parse_psk_modes(data: &[u8]) -> Result<Extension<'_>, Error> {
	let mut r = Reader::new(data);
	let list_len = r.read_u8("PSK modes length")? as usize;
	let list_data = r.read_bytes(list_len, "PSK modes data")?;
	Ok(Extension::PskExchangeModes(list_data.to_vec()))
}

fn parse_key_share<'a>(data: &'a [u8], has_grease: &mut bool) -> Result<Extension<'a>, Error> {
	let mut r = Reader::new(data);
	let list_len = r.read_u16("key share list length")? as usize;
	let list_data = r.read_bytes(list_len, "key share list data")?;
	let mut inner = Reader::new(list_data);
	let mut groups = Vec::new();
	while inner.remaining() >= 4 {
		let group = inner.read_u16("key share group")?;
		let key_len = inner.read_u16("key share key length")? as usize;
		let _key = inner.read_bytes(key_len, "key share key data")?;
		if is_grease(group) {
			*has_grease = true;
		} else {
			groups.push(group);
		}
	}
	Ok(Extension::KeyShareGroups(groups))
}

fn parse_u16_list_filtered(data: &[u8], has_grease: &mut bool) -> Result<Vec<u16>, Error> {
	let mut r = Reader::new(data);
	let list_len = r.read_u16("u16 list length")? as usize;
	let list_data = r.read_bytes(list_len, "u16 list data")?;
	let mut inner = Reader::new(list_data);
	let mut values = Vec::new();
	while inner.remaining() >= 2 {
		let val = inner.read_u16("u16 list entry")?;
		if is_grease(val) {
			*has_grease = true;
		} else {
			values.push(val);
		}
	}
	Ok(values)
}

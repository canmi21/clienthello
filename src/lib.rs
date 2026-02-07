/* src/lib.rs */

//! Zero-copy TLS ClientHello parser.
//!
//! Supports two input formats:
//!
//! - TLS records with a record-layer header (first byte `0x16`) via
//!   [`parse_from_record`].
//! - Raw handshake messages without a record layer (first byte `0x01`)
//!   via [`parse`], suitable for QUIC CRYPTO frames.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod error;
mod extension;
mod grease;
mod parser;
mod reader;

use alloc::vec::Vec;

pub use crate::error::Error;
pub use crate::extension::{Extension, ServerName};
pub use crate::grease::is_grease;
pub use crate::parser::{parse, parse_from_record};

/// Parsed TLS ClientHello message holding zero-copy references into the
/// original byte buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello<'a> {
	/// Legacy protocol version (usually `0x0303` for TLS 1.2).
	pub legacy_version: u16,
	/// 32-byte client random.
	pub random: &'a [u8],
	/// Session ID (may be empty).
	pub session_id: &'a [u8],
	/// Cipher suite identifiers with GREASE values removed.
	pub cipher_suites: Vec<u16>,
	/// Compression method bytes.
	pub compression_methods: &'a [u8],
	/// Parsed extensions.
	pub extensions: Vec<Extension<'a>>,
	/// Set to `true` when any GREASE value was encountered during parsing.
	pub has_grease: bool,
}

impl<'a> ClientHello<'a> {
	/// Return the first DNS hostname from the SNI extension.
	#[must_use]
	pub fn server_name(&self) -> Option<&str> {
		for ext in &self.extensions {
			if let Extension::ServerName(names) = ext {
				for sn in names {
					if sn.name_type == 0x00 {
						return core::str::from_utf8(sn.name).ok();
					}
				}
			}
		}
		None
	}

	/// Collect all ALPN protocol identifiers.
	#[must_use]
	pub fn alpn_protocols(&self) -> &[&[u8]] {
		for ext in &self.extensions {
			if let Extension::Alpn(protos) = ext {
				return protos;
			}
		}
		&[]
	}

	/// Return supported TLS versions (GREASE values already excluded).
	#[must_use]
	pub fn supported_versions(&self) -> &[u16] {
		for ext in &self.extensions {
			if let Extension::SupportedVersions(v) = ext {
				return v;
			}
		}
		&[]
	}

	/// Return supported groups / named curves (GREASE values already excluded).
	#[must_use]
	pub fn supported_groups(&self) -> &[u16] {
		for ext in &self.extensions {
			if let Extension::SupportedGroups(v) = ext {
				return v;
			}
		}
		&[]
	}

	/// Return signature algorithm identifiers.
	#[must_use]
	pub fn signature_algorithms(&self) -> &[u16] {
		for ext in &self.extensions {
			if let Extension::SignatureAlgorithms(v) = ext {
				return v;
			}
		}
		&[]
	}

	/// Return key-share group identifiers (GREASE values already excluded).
	#[must_use]
	pub fn key_share_groups(&self) -> &[u16] {
		for ext in &self.extensions {
			if let Extension::KeyShareGroups(v) = ext {
				return v;
			}
		}
		&[]
	}

	/// Check whether a renegotiation info extension is present.
	#[must_use]
	pub fn has_renegotiation_info(&self) -> bool {
		self
			.extensions
			.iter()
			.any(|ext| matches!(ext, Extension::RenegotiationInfo(_)))
	}

	/// Find the raw data of an extension by its type identifier.
	///
	/// Searches unknown extensions and renegotiation info. Returns
	/// `None` for extension types that were parsed into structured
	/// variants.
	#[must_use]
	pub fn find_extension(&self, type_id: u16) -> Option<&[u8]> {
		self.extensions.iter().find_map(|ext| match ext {
			Extension::RenegotiationInfo(data) if type_id == 0xFF01 => Some(*data),
			Extension::Unknown { type_id: id, data } if *id == type_id => Some(*data),
			_ => None,
		})
	}
}

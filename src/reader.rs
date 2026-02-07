/* src/reader.rs */

use crate::Error;

/// Sequential byte reader with bounds checking.
pub(crate) struct Reader<'a> {
	data: &'a [u8],
	pos: usize,
}

impl<'a> Reader<'a> {
	pub(crate) fn new(data: &'a [u8]) -> Self {
		Self { data, pos: 0 }
	}

	pub(crate) fn remaining(&self) -> usize {
		self.data.len() - self.pos
	}

	pub(crate) fn read_u8(&mut self, field: &'static str) -> Result<u8, Error> {
		if self.remaining() < 1 {
			return Err(Error::Truncated { field });
		}
		let val = self.data[self.pos];
		self.pos += 1;
		Ok(val)
	}

	pub(crate) fn read_u16(&mut self, field: &'static str) -> Result<u16, Error> {
		if self.remaining() < 2 {
			return Err(Error::Truncated { field });
		}
		let val = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
		self.pos += 2;
		Ok(val)
	}

	pub(crate) fn read_u24(&mut self, field: &'static str) -> Result<u32, Error> {
		if self.remaining() < 3 {
			return Err(Error::Truncated { field });
		}
		let val = u32::from_be_bytes([
			0,
			self.data[self.pos],
			self.data[self.pos + 1],
			self.data[self.pos + 2],
		]);
		self.pos += 3;
		Ok(val)
	}

	pub(crate) fn read_bytes(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], Error> {
		if self.remaining() < n {
			return Err(Error::Truncated { field });
		}
		let slice = &self.data[self.pos..self.pos + n];
		self.pos += n;
		Ok(slice)
	}
}

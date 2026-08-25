//! Shared-frame codec per "WEB proxy protocol v1" (PROTOCOL.md).
//!
//! Wire format:
//! ```text
//! type:u8 | stream_id:u24 | payload_length:u32 | payload
//! ```
//! All integers unsigned big-endian.

use thiserror::Error;

pub const TYPE_OPEN: u8 = 0x01;
pub const TYPE_DATA: u8 = 0x02;
pub const TYPE_CLOSE: u8 = 0x03;
pub const TYPE_WINDOW: u8 = 0x04;
pub const TYPE_PING: u8 = 0x05;
pub const TYPE_PONG: u8 = 0x06;
pub const TYPE_HELLO: u8 = 0x10;
pub const TYPE_WELCOME: u8 = 0x11;
pub const TYPE_BYE: u8 = 0x1f;

/// Maximum frame payload size we accept (limits.apply from the plan).
pub const MAX_FRAME_PAYLOAD: usize = 1 << 20; // 1 MiB

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: u8,
    pub stream_id: u32, // u24
    pub payload: Vec<u8>,
}

impl Frame {
    pub const HEADER_LEN: usize = 8; // 1 + 3 + 4

    pub fn new(ty: u8, stream_id: u32, payload: Vec<u8>) -> Self {
        debug_assert!(stream_id <= 0xFF_FFFF);
        Self {
            ty,
            stream_id,
            payload,
        }
    }

    /// Serialize to the 8-byte header + payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());
        out.push(self.ty);
        out.extend_from_slice(&[
            (self.stream_id >> 16) as u8,
            (self.stream_id >> 8) as u8,
            self.stream_id as u8,
        ]);
        let plen = self.payload.len() as u32;
        out.extend_from_slice(&plen.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a single complete frame at the start of `buf`.
    /// Returns `None` if more bytes are needed. Returns `Err` on malformed input.
    pub fn decode(buf: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
        if buf.len() < Self::HEADER_LEN {
            return Ok(None);
        }
        let ty = buf[0];
        let stream_id = ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | buf[3] as u32;
        let plen = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        if plen > MAX_FRAME_PAYLOAD {
            return Err(FrameError::Oversized(plen));
        }
        if buf.len() < Self::HEADER_LEN + plen {
            return Ok(None);
        }
        let payload = buf[Self::HEADER_LEN..Self::HEADER_LEN + plen].to_vec();
        let frame = Frame {
            ty,
            stream_id,
            payload,
        };
        Ok(Some((frame, Self::HEADER_LEN + plen)))
    }

    /// Decode a whole buffer that must contain exactly one frame.
    pub fn decode_one(buf: &[u8]) -> Result<Frame, FrameError> {
        match Self::decode(buf) {
            Ok(Some((f, used))) if used == buf.len() => Ok(f),
            Ok(Some((_, used))) => Err(FrameError::Trailing(used)),
            Ok(None) => Err(FrameError::Incomplete),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum FrameError {
    #[error("incomplete frame")]
    Incomplete,
    #[error("trailing bytes after frame")]
    Trailing(usize),
    #[error("payload too large: {0}")]
    Oversized(usize),
}

/// Parse a batch of frames (e.g. one WebSocket binary message) into frames.
pub fn decode_batch(buf: &[u8]) -> Result<Vec<Frame>, FrameError> {
    let mut out = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        match Frame::decode(rest)? {
            Some((f, used)) => {
                out.push(f);
                rest = &rest[used..];
            }
            None => return Err(FrameError::Incomplete),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_data() {
        let f = Frame::new(TYPE_DATA, 0xABCDEF, vec![1, 2, 3, 4, 5]);
        let enc = f.encode();
        assert_eq!(enc.len(), 8 + 5);
        let (back, used) = Frame::decode(&enc).unwrap().unwrap();
        assert_eq!(used, enc.len());
        assert_eq!(back, f);
    }

    #[test]
    fn header_big_endian() {
        let f = Frame::new(TYPE_OPEN, 0x010203, vec![]);
        let enc = f.encode();
        assert_eq!(&enc[..8], &[0x01, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn incomplete_returns_none() {
        let f = Frame::new(TYPE_DATA, 1, vec![9; 10]);
        let enc = f.encode();
        assert_eq!(Frame::decode(&enc[..enc.len() - 1]).unwrap(), None);
    }

    #[test]
    fn oversized_rejected() {
        let mut buf = vec![TYPE_DATA, 0, 0, 1];
        buf.extend_from_slice(&(MAX_FRAME_PAYLOAD as u32 + 1).to_be_bytes());
        assert_eq!(
            Frame::decode(&buf),
            Err(FrameError::Oversized(MAX_FRAME_PAYLOAD + 1))
        );
    }

    #[test]
    fn batch() {
        let a = Frame::new(TYPE_PING, 0, vec![42]);
        let b = Frame::new(TYPE_DATA, 3, vec![9, 9]);
        let mut buf = a.encode();
        buf.extend_from_slice(&b.encode());
        let parsed = decode_batch(&buf).unwrap();
        assert_eq!(parsed, vec![a, b]);
    }

    #[test]
    fn control_types() {
        for ty in [TYPE_PING, TYPE_PONG, TYPE_HELLO, TYPE_WELCOME, TYPE_BYE] {
            let f = Frame::new(ty, 0, vec![]);
            let enc = f.encode();
            assert_eq!(enc[0], ty);
        }
    }
}

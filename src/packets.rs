/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use crate::{Error, Result};
use core::convert::TryFrom;
use ed25519::{PublicKey, Signature, Verifier};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use sp4r53::Hash;

// ========================================= Interfaces ========================================= \\

pub trait Packet: Encode + Decode {
    const PACKET_ID: PacketId;
}

pub trait Encode {
    fn encode(&self, buf: &mut [u8]) -> Result<usize>;
}

pub trait Decode: Sized {
    fn decode(buf: &[u8]) -> Result<(Self, usize)>;
}

// ============================================ Types =========================================== \\

#[repr(u16)]
#[derive(Eq, PartialEq, IntoPrimitive, TryFromPrimitive, Copy, Clone)]
pub enum PacketId {
    Hello = 0,
}

/// ## Encoding
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// +         Packet ID (0)         |                               |  4
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |  8
/// +                                                               +
/// |                                                               | 12
/// +                                                               +
/// |                                                               | 16
/// +                                                               +
/// |                                                               | 20
/// +                            Node ID                            +
/// |                                                               | 24
/// +                                                               +
/// |                                                               | 28
/// +                                                               +
/// |                                                               | 32
/// +                                                               +
/// |                                                               | 36
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               | 40
/// +                                                               +
///
///                               {Root}
///
/// +                                                               +
/// |                                                               | 130
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct Hello {
    id: PublicKey,
    root: Root,
}

/// ## Encoding
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |  4
/// +                                                               +
/// |                                                               |  8
/// +                                                               +
/// |                                                               | 12
/// +                                                               +
/// |                                                               | 16
/// +                           Root Hash                           +
/// |                                                               | 20
/// +                                                               +
/// |                                                               | 24
/// +                                                               +
/// |                                                               | 28
/// +                                                               +
/// |                                                               | 32
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               | 36
/// +                                                               +
/// |                                                               | 40
/// +                                                               +
/// |                                                               | 44
/// +                                                               +
/// |                                                               | 48
/// +                                                               +
/// |                                                               | 52
/// +                                                               +
/// |                                                               | 56
/// +                                                               +
/// |                                                               | 60
/// +                                                               +
/// |                                                               | 64
/// +                           Signature                           +
/// |                                                               | 68
/// +                                                               +
/// |                                                               | 72
/// +                                                               +
/// |                                                               | 76
/// +                                                               +
/// |                                                               | 80
/// +                                                               +
/// |                                                               | 84
/// +                                                               +
/// |                                                               | 88
/// +                                                               +
/// |                                                               | 92
/// +                                                               +
/// |                                                               | 96
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct Root {
    hash: Hash,
    sig: Signature,
}

// ========================================= impl Packet ======================================== \\

impl Packet for Hello {
    const PACKET_ID: PacketId = PacketId::Hello;
}

// =========================================== Encode =========================================== \\

impl Encode for PacketId {
    fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 2 {
            return Err(Error::BufferSize {
                min: 2,
                actual: buf.len(),
            });
        }

        buf[0..2].copy_from_slice(&(*self as u16).to_le_bytes());

        Ok(2)
    }
}

impl Encode for Hello {
    fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let mut offset = 0;
        offset += Self::PACKET_ID.encode(&mut buf[offset..])?;
        offset += 2;
        offset += self.id.encode(&mut buf[offset..])?;
        offset += self.root.encode(&mut buf[offset..])?;

        Ok(offset)
    }
}

impl Encode for Root {
    fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let mut offset = 0;
        offset += self.hash.encode(&mut buf[offset..])?;
        offset += self.sig.encode(&mut buf[offset..])?;

        Ok(offset)
    }
}

impl Encode for Hash {
    fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 32 {
            return Err(Error::BufferSize {
                min: 32,
                actual: buf.len(),
            });
        }

        buf[0..32].copy_from_slice(self.as_bytes());

        Ok(32)
    }
}

impl Encode for PublicKey {
    fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 32 {
            return Err(Error::BufferSize {
                min: 32,
                actual: buf.len(),
            });
        }

        buf[0..32].copy_from_slice(self.as_bytes());

        Ok(32)
    }
}

impl Encode for Signature {
    fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 64 {
            return Err(Error::BufferSize {
                min: 64,
                actual: buf.len(),
            });
        }

        buf[0..64].copy_from_slice(&self.to_bytes());

        Ok(64)
    }
}

// ========================================= impl Decode ======================================== \\

impl Decode for PacketId {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 2 {
            return Err(Error::BufferSize {
                min: 2,
                actual: buf.len(),
            });
        }

        Ok((PacketId::try_from(u16::from_le_bytes([buf[0], buf[1]]))?, 2))
    }
}

impl Decode for Hello {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        let mut offset = 0;

        let (packet, bytes) = PacketId::decode(&buf[offset..])?;
        if packet != Self::PACKET_ID {
            return Err(Error::PacketId(packet));
        }

        offset += bytes;
        offset += 2;

        let (id, bytes) = PublicKey::decode(&buf[offset..])?;
        offset += bytes;

        let (root, bytes) = Root::decode(&buf[offset..])?;
        offset += bytes;

        Ok((Hello { id, root }, offset))
    }
}

impl Decode for Root {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        let mut offset = 0;

        let (hash, bytes) = Hash::decode(&buf[offset..])?;
        offset += bytes;

        let (sig, bytes) = Signature::decode(&buf[offset..])?;
        offset += bytes;

        Ok((Root { hash, sig }, offset))
    }
}

impl Decode for Hash {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 32 {
            return Err(Error::BufferSize {
                min: 32,
                actual: buf.len(),
            });
        }

        Ok((Hash::from(<[u8; 32]>::try_from(&buf[0..32]).unwrap()), 32))
    }
}

impl Decode for PublicKey {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 32 {
            return Err(Error::BufferSize {
                min: 32,
                actual: buf.len(),
            });
        }

        Ok((PublicKey::from_bytes(&buf[0..32])?, 32))
    }
}

impl Decode for Signature {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 64 {
            return Err(Error::BufferSize {
                min: 64,
                actual: buf.len(),
            });
        }

        Ok((Signature::try_from(&buf[0..64])?, 64))
    }
}

// ========================================= impl Hello ========================================= \\

impl Hello {
    // ==================================== Constructors ==================================== \\

    pub const fn new(id: PublicKey, root: Root) -> Self {
        Hello { id, root }
    }

    // ======================================== Read ======================================== \\

    #[inline]
    pub fn id(&self) -> &PublicKey {
        &self.id
    }

    #[inline]
    pub fn root(&self) -> &Root {
        &self.root
    }

    pub fn verify(&self) -> Result<()> {
        self.root.verify_for(&self.id)
    }
}

// ========================================== impl Root ========================================= \\

impl Root {
    // ==================================== Constructors ==================================== \\

    pub const fn new(hash: Hash, sig: Signature) -> Self {
        Root { hash, sig }
    }

    // ======================================== Read ======================================== \\

    #[inline]
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    #[inline]
    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    pub fn verify_for(&self, id: &PublicKey) -> Result<()> {
        Ok(id.verify(self.hash.as_bytes(), &self.root.sig)?)
    }
}

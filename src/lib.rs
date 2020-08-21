/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use async_peek::{AsyncPeek, AsyncPeekExt};
use futures_util::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use packets::{Decode, Packet, PacketId, MSG_MAX_LEN, NOISE_OVERHEAD, RAW_MAX_LEN};
use snow::{HandshakeState, TransportState};

#[cfg(feature = "thiserror")]
use thiserror::Error;

// ============================================ Types =========================================== \\

pub struct Handshake {
    state: TransportState,
}

pub struct Protocol {
    buf: Vec<u8>,
    msg: Vec<u8>,
    next: usize,
    state: TransportState,
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(Error))]
pub enum Error {
    #[cfg_attr(feature = "thiserror", error("buffer is too small (min={min};actual={actual})"))]
    BufferSize {
        min: usize,
        actual: usize,
    },
    #[cfg_attr(feature = "thiserror", error("invalid data size (max={max};actual={actual})"))]
    InvalidSize {
        max: usize,
        actual: usize,
    },
    #[cfg_attr(feature = "thiserror", error("io-related error ({0})"))]
    Io(io::Error),
    #[cfg_attr(feature = "thiserror", error("noise-related error ({0})"))]
    Noise(snow::Error),
    #[cfg_attr(feature = "thiserror", error("p4ck375-related error ({0})"))]
    P4ck375(packets::Error),
}

// ========================================= Interfaces ========================================= \\

trait NoiseState {
    fn is_handshake(&self) -> bool;

    fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize>;

    fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize>;
}

// =========================================== Helpers ========================================== \\

async fn read<I, S>(
    mut input: I,
    state: &mut S,
    buf: &mut [u8],
    msg: &mut [u8],
) -> Result<usize>
where
    I: AsyncPeek + AsyncRead + Unpin,
    S: NoiseState,
{
    let read = input.peek(&mut buf[0..2]).await?;
    if read != 2 {
        panic!("read != 2"); // FIXME
    }

    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if len > RAW_MAX_LEN {
        return Err(Error::InvalidSize {
            max: RAW_MAX_LEN,
            actual: len,
        });
    } else if len - NOISE_OVERHEAD > msg.len() && !state.is_handshake() {
        // FIXME: handshake payload
        return Err(Error::BufferSize {
            min: len - NOISE_OVERHEAD,
            actual: msg.len(),
        });
    } else if len > buf.len() {
        return Err(Error::BufferSize {
            min: len,
            actual: buf.len(),
        });
    }

    input.read_exact(&mut buf[..2]).await?;
    input.read_exact(&mut buf[..len]).await?;
    Ok(state.read_message(&buf[..len], msg)?)
}

async fn write<O, S>(
    mut output: O,
    state: &mut S,
    buf: &mut [u8],
    msg: &[u8],
) -> Result<usize>
where
    O: AsyncWrite + Unpin,
    S: NoiseState,
{
    if msg.len() > MSG_MAX_LEN {
        return Err(Error::InvalidSize {
            max: MSG_MAX_LEN,
            actual: msg.len(),
        });
    } else if msg.len() + NOISE_OVERHEAD > buf.len() {
        return Err(Error::BufferSize {
            min: msg.len() + NOISE_OVERHEAD,
            actual: buf.len(),
        });
    }

    let len = state.write_message(&msg, buf)?;
    output.write_all(&(len as u16).to_le_bytes()).await?;
    output.write_all(&buf[..len]).await?;

    Ok(len + 2)
}

// ======================================= impl Handshake ======================================= \\

impl Handshake {
    // ====================================== Constants ===================================== \\

    pub const NOISE_PATTERN: &'static str = "Noise_NN_25519_ChaChaPoly_BLAKE2b";

    // ==================================== Constructors ==================================== \\

    pub async fn initiate<I, O>(input: I, mut output: O) -> Result<Self>
    where
        I: AsyncPeek + AsyncRead + Unpin,
        O: AsyncWrite + Unpin,
    {
        let mut state = snow::Builder::new(Self::NOISE_PATTERN.parse().unwrap())
            .build_initiator()?;

        // -> e     ; 56 bytes
        // <- e, ee ; 72 bytes
        let mut buf = [0; 72];

        write(&mut output, &mut state, &mut buf, &[]).await?;
        output.flush().await?;
        read(input, &mut state, &mut buf, &mut []).await?;

        Ok(Handshake {
            state: state.into_transport_mode()?,
        })
    }

    pub async fn respond<I, O>(input: I, mut output: O) -> Result<Self>
    where
        I: AsyncPeek + AsyncRead + Unpin,
        O: AsyncWrite + Unpin,
    {
        let mut state = snow::Builder::new(Self::NOISE_PATTERN.parse().unwrap())
            .build_responder()?;

        // -> e     ; 56 bytes
        // <- e, ee ; 72 bytes
        let mut buf = [0; 72];

        read(input, &mut state, &mut buf, &mut []).await?;
        write(&mut output, &mut state, &mut buf, &[]).await?;
        output.flush().await?;

        Ok(Handshake {
            state: state.into_transport_mode()?,
        })
    }

    // ===================================== Destructors ==================================== \\

    pub fn done(self) -> Protocol {
        Protocol {
            buf: vec![0; RAW_MAX_LEN],
            msg: vec![0; MSG_MAX_LEN],
            next: 0,
            state: self.state,
        }
    }
}

// ======================================== impl Protocol ======================================= \\

impl Protocol {
    // ===================================== Read+Write ===================================== \\

    pub async fn send<O, P>(&mut self, output: O, packet: P) -> Result<usize>
    where
        O: AsyncWrite + Unpin,
        P: Packet,
    {
        let len = packet.encode(&mut self.msg)?;
        write(output, &mut self.state, &mut self.buf, &self.msg[0..len]).await
    }

    pub async fn try_recv<I, P>(&mut self, input: I) -> Result<P>
    where
        I: AsyncPeek + AsyncRead + Unpin,
        P: Packet,
    {
        let packet_id = self.peek_packet_id(input).await?;
        if packet_id != P::PACKET_ID {
            return Err(packets::Error::WrongPacketId(packet_id).into());
        }

        match P::decode(&self.msg[0..self.next]) {
            Ok((packet, bytes)) => {
                self.next -= bytes;
                Ok(packet)
            }
            Err(err) => {
                self.next = 0;
                Err(err.into())
            }
        }
    }

    pub async fn peek_packet_id<I>(&mut self, input: I) -> Result<PacketId>
    where
        I: AsyncPeek + AsyncRead + Unpin,
    {
        if self.next == 0 {
            self.next = read(input, &mut self.state, &mut self.buf, &mut self.msg).await?;
        }

        match PacketId::decode(&self.msg[0..self.next]) {
            Ok((packet, _)) => Ok(packet),
            Err(err) => {
                self.next = 0;
                Err(err.into())
            }
        }
    }
}

// ========================================== impl From ========================================= \\

impl From<io::Error> for Error {
    #[inline]
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

impl From<snow::Error> for Error {
    #[inline]
    fn from(error: snow::Error) -> Self {
        Error::Noise(error)
    }
}

impl From<packets::Error> for Error {
    #[inline]
    fn from(error: packets::Error) -> Self {
        Error::P4ck375(error)
    }
}

// ======================================= impl NoiseState ====================================== \\

impl NoiseState for HandshakeState {
    #[inline]
    fn is_handshake(&self) -> bool {
        true
    }

    #[inline]
    fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize> {
        Ok(self.read_message(message, payload)?)
    }

    #[inline]
    fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize> {
        Ok(self.write_message(payload, message)?)
    }
}

impl NoiseState for TransportState {
    #[inline]
    fn is_handshake(&self) -> bool {
        false
    }

    #[inline]
    fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize> {
        Ok(self.read_message(message, payload)?)
    }

    #[inline]
    fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize> {
        Ok(self.write_message(payload, message)?)
    }
}

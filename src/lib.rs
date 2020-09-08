/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

mod initiate;
mod read;
mod recv;
mod respond;
mod send;
mod write;

pub use self::initiate::Initiate;
pub use self::recv::Recv;
pub use self::respond::Respond;
pub use self::send::Send;
pub use packets::{self, Packet};

pub(crate) use self::read::Read;
pub(crate) use self::write::Write;

use async_peek::AsyncPeek;
use futures_io::{AsyncRead, AsyncWrite};
use packets::{MSG_MAX_LEN, NOISE_MAX_LEN};
use snow::{HandshakeState, TransportState};
use std::io;

#[cfg(feature = "thiserror")]
use thiserror::Error;

// ============================================ Types =========================================== \\

pub struct Handshake {
    state: HandshakeState,
}

pub struct Protocol {
    buf: Vec<u8>,
    msg: Vec<u8>,
    state: TransportState,
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(Error))]
pub enum Error {
    #[cfg_attr(feature = "thiserror", error("buffer size is too small (min={min}, actual={actual})"))]
    BufferSize { min: usize, actual: usize },
    #[cfg_attr(feature = "thiserror", error("io-related error ({0})"))]
    Io(io::Error),
    #[cfg_attr(feature = "thiserror", error("message size is too large (max={max}, actual={actual})"))]
    MessageSize { max: usize, actual: usize },
    #[cfg_attr(feature = "thiserror", error("noise-related error ({0})"))]
    Noise(snow::Error),
    #[cfg_attr(feature = "thiserror", error("p4ck375-related error ({0})"))]
    P4ck375(packets::Error),
}

// ========================================= Interfaces ========================================= \\

trait NoiseState {
    const IS_HANDSHAKE: bool;

    fn read_message(&mut self, buf: &[u8], msg: &mut [u8]) -> Result<usize>;

    fn write_message(&mut self, msg: &[u8], buf: &mut [u8]) -> Result<usize>;
}

// ======================================= impl Handshake ======================================= \\

impl Handshake {
    // ====================================== Constants ===================================== \\

    pub const NOISE_PATTERN: &'static str = "Noise_NN_25519_ChaChaPoly_BLAKE2b";

    // ==================================== Constructors ==================================== \\

    pub fn initiate<Input, Output>(input: Input, output: Output) -> Initiate<Input, Output>
    where
        Input: AsyncPeek + AsyncRead + Unpin,
        Output: AsyncWrite + Unpin,
    {
        Initiate::new(input, output)
    }

    pub fn respond<Input, Output>(input: Input, output: Output) -> Respond<Input, Output>
    where
        Input: AsyncPeek + AsyncRead + Unpin,
        Output: AsyncWrite + Unpin,
    {
        Respond::new(input, output)
    }

    // ===================================== Destructors ==================================== \\

    pub fn done(self) -> Result<Protocol> {
        Ok(Protocol {
            buf: vec![0; NOISE_MAX_LEN],
            msg: vec![0; MSG_MAX_LEN],
            state: self.state.into_transport_mode()?,
        })
    }
}

// ======================================== impl Protocol ======================================= \\

impl Protocol {
    // ===================================== Read+Write ===================================== \\

    pub fn send<Output>(&mut self, output: Output, packet: Packet) -> Send<'_, Output>
    where
        Output: AsyncWrite + Unpin,
    {
        Send::new(packet, self, output)
    }

    pub fn recv<Input>(&mut self, input: Input) -> Recv<'_, Input>
    where
        Input: AsyncPeek + AsyncRead + Unpin,
    {
        Recv::new(self, input)
    }
}

// ======================================= impl NoiseState ====================================== \\

impl NoiseState for HandshakeState {
    const IS_HANDSHAKE: bool = true;

    #[inline]
    fn read_message(&mut self, buf: &[u8], msg: &mut [u8]) -> Result<usize> {
        Ok(self.read_message(buf, msg)?)
    }

    #[inline]
    fn write_message(&mut self, msg: &[u8], buf: &mut [u8]) -> Result<usize> {
        Ok(self.write_message(msg, buf)?)
    }
}

impl NoiseState for TransportState {
    const IS_HANDSHAKE: bool = false;

    #[inline]
    fn read_message(&mut self, buf: &[u8], msg: &mut [u8]) -> Result<usize> {
        Ok(self.read_message(buf, msg)?)
    }

    #[inline]
    fn write_message(&mut self, msg: &[u8], buf: &mut [u8]) -> Result<usize> {
        Ok(self.write_message(msg, buf)?)
    }
}

impl<State: NoiseState> NoiseState for &mut State {
    const IS_HANDSHAKE: bool = State::IS_HANDSHAKE;

    #[inline]
    fn read_message(&mut self, buf: &[u8], msg: &mut [u8]) -> Result<usize> {
        State::read_message(*self, buf, msg)
    }

    #[inline]
    fn write_message(&mut self, msg: &[u8], buf: &mut [u8]) -> Result<usize> {
        State::write_message(*self, msg, buf)
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

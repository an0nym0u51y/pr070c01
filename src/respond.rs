/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use crate::{Handshake, Read, Result, Write};
use async_peek::AsyncPeek;
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_io::{AsyncRead, AsyncWrite};
use snow::HandshakeState;

// ============================================ Types =========================================== \\

pub struct Respond<IO> {
    inner: RespondInner<IO>,
}

enum RespondInner<IO> {
    Empty,
    State {
        io: IO,
    },
    Read {
        read: Read<IO, HandshakeState>,
    },
    Write {
        write: Write<IO, HandshakeState>,
    },
    Flush {
        io: IO,
        state: HandshakeState,
    },
    Done {
        io: IO,
    },
}

// ======================================== impl Respond ======================================== \\

impl<IO> Respond<IO> {
    // ==================================== Constructors ==================================== \\

    #[inline]
    pub(super) fn new(io: IO) -> Self
    where
        IO: AsyncPeek + AsyncRead + AsyncWrite + Unpin,
    {
        Respond {
            inner: RespondInner::State { io },
        }
    }

    // ===================================== Destructors ==================================== \\

    pub fn done(self) -> IO {
        match self.inner {
            RespondInner::Empty => panic!(),
            RespondInner::State { io }
            | RespondInner::Flush { io, .. }
            | RespondInner::Done { io } => io,
            RespondInner::Read { read } => read.done().2,
            RespondInner::Write { write } => write.done().2,
        }
    }
}

// ========================================= impl Future ======================================== \\

impl<IO> Future for Respond<IO>
where
    IO: AsyncPeek + AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<Handshake>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        loop {
            match mem::take(inner) {
                RespondInner::Empty | RespondInner::Done { .. } => panic!(),
                RespondInner::State { io } => {
                    let state = snow::Builder::new(Handshake::NOISE_PATTERN.parse().unwrap())
                        .build_responder()?;

                    // -> e     ;; 56 bytes
                    // <- e, ee ;; 72 bytes
                    let buf = vec![0; 72];

                    *inner = RespondInner::Read {
                        read: Read::new(Vec::new(), buf, io, state),
                    };
                }
                RespondInner::Read { mut read } => {
                    if Pin::new(&mut read).poll(ctx)?.is_ready() {
                        let (_, buf, io, state) = read.done();

                        *inner = RespondInner::Write {
                            write: Write::new(Vec::new(), buf, io, state),
                        };
                    } else {
                        *inner = RespondInner::Read { read };

                        return Poll::Pending;
                    }
                }
                RespondInner::Write { mut write } => {
                    if Pin::new(&mut write).poll(ctx)?.is_ready() {
                        let (_, _, io, state) = write.done();

                        *inner = RespondInner::Flush { io, state };
                    } else {
                        *inner = RespondInner::Write { write };

                        return Poll::Pending;
                    }
                }
                RespondInner::Flush { mut io, state } => {
                    if Pin::new(&mut io).poll_flush(ctx)?.is_ready() {
                        *inner = RespondInner::Done { io };

                        return Poll::Ready(Ok(Handshake { state }));
                    } else {
                        *inner = RespondInner::Flush { io, state };

                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

// ======================================== impl Default ======================================== \\

impl<IO> Default for RespondInner<IO> {
    #[inline]
    fn default() -> Self {
        RespondInner::Empty
    }
}

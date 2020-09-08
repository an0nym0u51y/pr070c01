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

pub struct Initiate<IO> {
    inner: InitiateInner<IO>,
}

enum InitiateInner<IO> {
    Empty,
    State {
        io: IO,
    },
    Write {
        write: Write<IO, HandshakeState>,
    },
    Flush {
        buf: Vec<u8>,
        io: IO,
        state: HandshakeState,
    },
    Read {
        read: Read<IO, HandshakeState>,
    },
    Done {
        io: IO,
    },
}

// ======================================== impl Initiate ======================================= \\

impl<IO> Initiate<IO> {
    // ==================================== Constructors ==================================== \\

    #[inline]
    pub(super) fn new(io: IO) -> Self
    where
        IO: AsyncPeek + AsyncRead + AsyncWrite + Unpin,
    {
        Initiate {
            inner: InitiateInner::State { io },
        }
    }

    // ===================================== Destructors ==================================== \\

    pub fn done(self) -> IO {
        match self.inner {
            InitiateInner::Empty => panic!(),
            InitiateInner::State { io }
            | InitiateInner::Flush { io, .. }
            | InitiateInner::Done { io } => io,
            InitiateInner::Write { write } => write.done().2,
            InitiateInner::Read { read } => read.done().2,
        }
    }
}

// ========================================= impl Future ======================================== \\

impl<IO> Future for Initiate<IO>
where
    IO: AsyncPeek + AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<Handshake>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        loop {
            match mem::take(inner) {
                InitiateInner::Empty | InitiateInner::Done { .. } => panic!(),
                InitiateInner::State { io } => {
                    let state = snow::Builder::new(Handshake::NOISE_PATTERN.parse().unwrap())
                        .build_initiator()?;

                    // -> e     ;; 56 bytes
                    // <- e, ee ;; 72 bytes
                    let buf = vec![0; 72];

                    *inner = InitiateInner::Write {
                        write: Write::new(Vec::new(), buf, io, state),
                    };
                }
                InitiateInner::Write { mut write } => {
                    if Pin::new(&mut write).poll(ctx)?.is_ready() {
                        let (_, buf, io, state) = write.done();

                        *inner = InitiateInner::Flush {
                            buf,
                            io,
                            state,
                        };
                    } else {
                        *inner = InitiateInner::Write { write };

                        return Poll::Pending;
                    }
                }
                InitiateInner::Flush {
                    buf,
                    mut io,
                    state,
                } => {
                    if Pin::new(&mut io).poll_flush(ctx)?.is_ready() {
                        *inner = InitiateInner::Read {
                            read: Read::new(Vec::new(), buf, io, state),
                        };
                    } else {
                        *inner = InitiateInner::Flush {
                            buf,
                            io,
                            state,
                        };

                        return Poll::Pending;
                    }
                }
                InitiateInner::Read { mut read } => {
                    if Pin::new(&mut read).poll(ctx)?.is_ready() {
                        let (_, _, io, state) = read.done();

                        *inner = InitiateInner::Done { io };

                        return Poll::Ready(Ok(Handshake { state }));
                    } else {
                        *inner = InitiateInner::Read { read };

                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

// ======================================== impl Default ======================================== \\

impl<IO> Default for InitiateInner<IO> {
    #[inline]
    fn default() -> Self {
        InitiateInner::Empty
    }
}

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

pub struct Initiate<Input, Output> {
    inner: InitiateInner<Input, Output>,
}

enum InitiateInner<Input, Output> {
    Empty,
    State {
        inp: Input,
        out: Output,
    },
    Write {
        inp: Input,
        write: Write<Output, HandshakeState>,
    },
    Flush {
        buf: Vec<u8>,
        inp: Input,
        out: Output,
        state: HandshakeState,
    },
    Read {
        read: Read<Input, HandshakeState>,
    },
}

// ======================================== impl Initiate ======================================= \\

impl<Input, Output> Initiate<Input, Output> {
    // ==================================== Constructors ==================================== \\

    #[inline]
    pub(super) fn new(inp: Input, out: Output) -> Self
    where
        Input: AsyncPeek + AsyncRead + Unpin,
        Output: AsyncWrite + Unpin,
    {
        Initiate {
            inner: InitiateInner::State { inp, out },
        }
    }
}

// ========================================= impl Future ======================================== \\

impl<Input, Output> Future for Initiate<Input, Output>
where
    Input: AsyncPeek + AsyncRead + Unpin,
    Output: AsyncWrite + Unpin,
{
    type Output = Result<Handshake>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        loop {
            match mem::take(inner) {
                InitiateInner::Empty => panic!(),
                InitiateInner::State { inp, out } => {
                    let state = snow::Builder::new(Handshake::NOISE_PATTERN.parse().unwrap())
                        .build_initiator()?;

                    // -> e     ;; 56 bytes
                    // <- e, ee ;; 72 bytes
                    let buf = vec![0; 72];

                    *inner = InitiateInner::Write {
                        inp,
                        write: Write::new(Vec::new(), buf, out, state),
                    };
                }
                InitiateInner::Write { inp, mut write } => {
                    if Pin::new(&mut write).poll(ctx)?.is_ready() {
                        let (_, buf, out, state) = write.done();

                        *inner = InitiateInner::Flush {
                            buf,
                            inp,
                            out,
                            state,
                        };
                    } else {
                        *inner = InitiateInner::Write { inp, write };

                        return Poll::Pending;
                    }
                }
                InitiateInner::Flush {
                    buf,
                    inp,
                    mut out,
                    state,
                } => {
                    if Pin::new(&mut out).poll_flush(ctx)?.is_ready() {
                        *inner = InitiateInner::Read {
                            read: Read::new(Vec::new(), buf, inp, state),
                        };
                    } else {
                        *inner = InitiateInner::Flush {
                            buf,
                            inp,
                            out,
                            state,
                        };

                        return Poll::Pending;
                    }
                }
                InitiateInner::Read { mut read } => {
                    if Pin::new(&mut read).poll(ctx)?.is_ready() {
                        let (_, _, _, state) = read.done();

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

impl<Input, Output> Default for InitiateInner<Input, Output> {
    #[inline]
    fn default() -> Self {
        InitiateInner::Empty
    }
}

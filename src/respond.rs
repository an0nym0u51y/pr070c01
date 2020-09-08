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

pub struct Respond<Input, Output> {
    inner: RespondInner<Input, Output>,
}

enum RespondInner<Input, Output> {
    Empty,
    State {
        inp: Input,
        out: Output,
    },
    Read {
        out: Output,
        read: Read<Input, HandshakeState>,
    },
    Write {
        write: Write<Output, HandshakeState>,
    },
    Flush {
        out: Output,
        state: HandshakeState,
    },
}

// ======================================== impl Respond ======================================== \\

impl<Input, Output> Respond<Input, Output> {
    // ==================================== Constructors ==================================== \\

    #[inline]
    pub(super) fn new(inp: Input, out: Output) -> Self
    where
        Input: AsyncPeek + AsyncRead + Unpin,
        Output: AsyncWrite + Unpin,
    {
        Respond {
            inner: RespondInner::State { inp, out },
        }
    }
}

// ========================================= impl Future ======================================== \\

impl<Input, Output> Future for Respond<Input, Output>
where
    Input: AsyncPeek + AsyncRead + Unpin,
    Output: AsyncWrite + Unpin,
{
    type Output = Result<Handshake>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        loop {
            match mem::take(inner) {
                RespondInner::Empty => panic!(),
                RespondInner::State { inp, out } => {
                    let state = snow::Builder::new(Handshake::NOISE_PATTERN.parse().unwrap())
                        .build_responder()?;

                    // -> e     ;; 56 bytes
                    // <- e, ee ;; 72 bytes
                    let buf = vec![0; 72];

                    *inner = RespondInner::Read {
                        out,
                        read: Read::new(Vec::new(), buf, inp, state),
                    };
                }
                RespondInner::Read { out, mut read } => {
                    if Pin::new(&mut read).poll(ctx)?.is_ready() {
                        let (_, buf, _, state) = read.done();

                        *inner = RespondInner::Write {
                            write: Write::new(Vec::new(), buf, out, state),
                        };
                    } else {
                        *inner = RespondInner::Read { out, read };

                        return Poll::Pending;
                    }
                }
                RespondInner::Write { mut write } => {
                    if Pin::new(&mut write).poll(ctx)?.is_ready() {
                        let (_, _, out, state) = write.done();

                        *inner = RespondInner::Flush { out, state };
                    } else {
                        *inner = RespondInner::Write { write };

                        return Poll::Pending;
                    }
                }
                RespondInner::Flush { mut out, state } => {
                    if Pin::new(&mut out).poll_flush(ctx)?.is_ready() {
                        return Poll::Ready(Ok(Handshake { state }));
                    } else {
                        *inner = RespondInner::Flush { out, state };

                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

// ======================================== impl Default ======================================== \\

impl<Input, Output> Default for RespondInner<Input, Output> {
    #[inline]
    fn default() -> Self {
        RespondInner::Empty
    }
}

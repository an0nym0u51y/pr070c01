/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use crate::{Protocol, Read, Result};
use async_peek::AsyncPeek;
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::task::{Context, Poll};
use format::Decode;
use futures_io::AsyncRead;
use packets::Packet;
use snow::TransportState;

// ============================================ Types =========================================== \\

pub struct Recv<'proto, Input> {
    inner: RecvInner<'proto, Input>,
}

enum RecvInner<'proto, Input> {
    Empty,
    Read {
        read: Read<Input, &'proto mut TransportState, &'proto mut Vec<u8>>,
    },
    Decode {
        len: usize,
        msg: &'proto mut Vec<u8>,
    },
}

// ========================================== impl Recv ========================================= \\

impl<'proto, Input> Recv<'proto, Input> {
    // ==================================== Constructors ==================================== \\

    pub(super) fn new(proto: &'proto mut Protocol, inp: Input) -> Self
    where
        Input: AsyncPeek + AsyncRead + Unpin,
    {
        Recv {
            inner: RecvInner::Read {
                read: Read::new(&mut proto.msg, &mut proto.buf, inp, &mut proto.state),
            },
        }
    }
}

// ========================================= impl Future ======================================== \\

impl<Input> Future for Recv<'_, Input>
where
    Input: AsyncPeek + AsyncRead + Unpin,
{
    type Output = Result<Packet>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        loop {
            match mem::take(inner) {
                RecvInner::Empty => panic!(),
                RecvInner::Read { mut read } => {
                    if let Poll::Ready(len) = Pin::new(&mut read).poll(ctx)? {
                        let (msg, _, _, _) = read.done();

                        *inner = RecvInner::Decode { len, msg };
                    } else {
                        *inner = RecvInner::Read { read };

                        return Poll::Pending;
                    }
                }
                RecvInner::Decode { len, msg } => {
                    return Poll::Ready(Ok(Packet::decode(&msg[..len])?.0));
                }
            }
        }
    }
}

// ======================================== impl Default ======================================== \\

impl<Input> Default for RecvInner<'_, Input> {
    #[inline]
    fn default() -> Self {
        RecvInner::Empty
    }
}

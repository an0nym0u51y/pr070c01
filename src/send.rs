/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use crate::{Protocol, Result, Write};
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::task::{Context, Poll};
use format::Encode;
use futures_io::AsyncWrite;
use packets::{Packet, MSG_MAX_LEN};
use snow::TransportState;

// ============================================ Types =========================================== \\

pub struct Send<'proto, Output> {
    inner: SendInner<'proto, Output>,
}

enum SendInner<'proto, Output> {
    Empty,
    Encode {
        packet: Packet,
        buf: &'proto mut Vec<u8>,
        msg: &'proto mut Vec<u8>,
        state: &'proto mut TransportState,
        out: Output,
    },
    Write {
        write: Write<Output, &'proto mut TransportState, &'proto mut Vec<u8>>,
    },
}

// ========================================== impl Send ========================================= \\

impl<'proto, Output> Send<'proto, Output> {
    // ==================================== Constructors ==================================== \\

    pub(super) fn new(packet: Packet, proto: &'proto mut Protocol, out: Output) -> Self
    where
        Output: AsyncWrite + Unpin,
    {
        Send {
            inner: SendInner::Encode {
                packet,
                buf: &mut proto.buf,
                msg: &mut proto.msg,
                state: &mut proto.state,
                out,
            },
        }
    }
}

// ========================================= impl Future ======================================== \\

impl<Output> Future for Send<'_, Output>
where
    Output: AsyncWrite + Unpin,
{
    type Output = Result<usize>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        loop {
            match mem::take(inner) {
                SendInner::Empty => panic!(),
                SendInner::Encode {
                    packet,
                    buf,
                    mut msg,
                    state,
                    out,
                } => {
                    msg.resize(MSG_MAX_LEN, 0);

                    let (bytes, _) = packet.encode(&mut msg)?;
                    msg.truncate(bytes);

                    *inner = SendInner::Write {
                        write: Write::new(msg, buf, out, state),
                    };
                }
                SendInner::Write { mut write } => {
                    if let Poll::Ready(wrote) = Pin::new(&mut write).poll(ctx)? {
                        return Poll::Ready(Ok(wrote));
                    } else {
                        *inner = SendInner::Write { write };

                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

// ======================================== impl Default ======================================== \\

impl<Output> Default for SendInner<'_, Output> {
    #[inline]
    fn default() -> Self {
        SendInner::Empty
    }
}

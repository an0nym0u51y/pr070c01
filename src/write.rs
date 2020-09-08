/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use crate::{Error, NoiseState, Result};
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_io::AsyncWrite;
use packets::{MSG_MAX_LEN, MSG_OVERHEAD};

// ============================================ Types =========================================== \\

pub(crate) struct Write<Output, State, Buf = Vec<u8>> {
    inner: WriteInner<Output, State, Buf>,
}

enum WriteInner<Output, State, Buf> {
    Empty,
    Prepare {
        msg: Buf,
        buf: Buf,
        out: Output,
        state: State,
    },
    Write {
        len: usize,
        offset: usize,
        msg: Buf,
        buf: Buf,
        out: Output,
        state: State,
    },
    Done {
        len: usize,
        msg: Buf,
        buf: Buf,
        out: Output,
        state: State,
    },
}

// ========================================= impl Write ========================================= \\

impl<Output, State, Buf> Write<Output, State, Buf> {
    // ==================================== Constructors ==================================== \\

    #[inline]
    pub(crate) fn new(msg: Buf, buf: Buf, out: Output, state: State) -> Self
    where
        Output: AsyncWrite + Unpin,
        State: NoiseState + Unpin,
        Buf: AsRef<[u8]> + AsMut<Vec<u8>> + Unpin,
    {
        Write {
            inner: WriteInner::Prepare {
                msg,
                buf,
                out,
                state,
            },
        }
    }

    // ===================================== Destructors ==================================== \\

    #[inline]
    pub(crate) fn done(self) -> (Buf, Buf, Output, State) {
        match self.inner {
            WriteInner::Empty => panic!(),
            WriteInner::Prepare {
                msg,
                buf,
                out,
                state,
                ..
            }
            | WriteInner::Write {
                msg,
                buf,
                out,
                state,
                ..
            }
            | WriteInner::Done {
                msg,
                buf,
                out,
                state,
                ..
            } => (msg, buf, out, state),
        }
    }
}

// ========================================= impl Future ======================================== \\

impl<Output, State, Buf> Future for Write<Output, State, Buf>
where
    Output: AsyncWrite + Unpin,
    State: NoiseState + Unpin,
    Buf: AsRef<[u8]> + AsMut<Vec<u8>> + Unpin,
{
    type Output = Result<usize>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        loop {
            match mem::take(inner) {
                WriteInner::Empty => panic!(),
                WriteInner::Prepare {
                    msg,
                    buf,
                    out,
                    state,
                } if msg.as_ref().len() > MSG_MAX_LEN => {
                    let err = Err(Error::MessageSize {
                        max: MSG_MAX_LEN,
                        actual: msg.as_ref().len(),
                    });

                    *inner = WriteInner::Done {
                        len: 0,
                        msg,
                        buf,
                        out,
                        state,
                    };

                    return err.into();
                }
                WriteInner::Prepare {
                    msg,
                    mut buf,
                    out,
                    state,
                } if msg.as_ref().len() + MSG_OVERHEAD > buf.as_ref().len() => {
                    buf.as_mut().resize(msg.as_ref().len() + MSG_OVERHEAD, 0);

                    *inner = WriteInner::Prepare {
                        msg,
                        buf,
                        out,
                        state,
                    };
                }
                WriteInner::Prepare {
                    msg,
                    mut buf,
                    out,
                    mut state,
                } => match state.write_message(msg.as_ref(), &mut buf.as_mut()[2..]) {
                    Ok(len) => {
                        buf.as_mut()[0..2].copy_from_slice(&(len as u16).to_le_bytes());

                        *inner = WriteInner::Write {
                            len: len + 2,
                            offset: 0,
                            msg,
                            buf,
                            out,
                            state,
                        };
                    }
                    Err(err) => {
                        *inner = WriteInner::Done {
                            len: 0,
                            msg,
                            buf,
                            out,
                            state,
                        };

                        return Poll::Ready(Err(err));
                    }
                },
                WriteInner::Write {
                    len,
                    offset,
                    msg,
                    buf,
                    out,
                    state,
                } if offset >= len => {
                    *inner = WriteInner::Done {
                        len,
                        msg,
                        buf,
                        out,
                        state,
                    };

                    return Poll::Ready(Ok(len));
                }
                WriteInner::Write {
                    len,
                    mut offset,
                    msg,
                    buf,
                    mut out,
                    state,
                } => match Pin::new(&mut out).poll_write(ctx, &buf.as_ref()[offset..len]) {
                    Poll::Ready(Ok(wrote)) => {
                        offset += wrote;

                        *inner = WriteInner::Write {
                            len,
                            offset,
                            msg,
                            buf,
                            out,
                            state,
                        };
                    }
                    Poll::Ready(Err(err)) => {
                        *inner = WriteInner::Done {
                            len: 0,
                            msg,
                            buf,
                            out,
                            state,
                        };

                        return Poll::Ready(Err(err.into()));
                    }
                    Poll::Pending => {
                        *inner = WriteInner::Write {
                            len,
                            offset,
                            msg,
                            buf,
                            out,
                            state,
                        };

                        return Poll::Pending;
                    }
                },
                WriteInner::Done {
                    len,
                    msg,
                    buf,
                    out,
                    state,
                } => {
                    *inner = WriteInner::Done {
                        len,
                        msg,
                        buf,
                        out,
                        state,
                    };

                    return Poll::Ready(Ok(len));
                }
            }
        }
    }
}

// ======================================== impl Default ======================================== \\

impl<Output, State, Buf> Default for WriteInner<Output, State, Buf> {
    #[inline]
    fn default() -> Self {
        WriteInner::Empty
    }
}

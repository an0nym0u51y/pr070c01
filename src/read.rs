/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use crate::{Error, NoiseState, Result};
use async_peek::AsyncPeek;
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_io::AsyncRead;
use packets::{NOISE_OVERHEAD, RAW_MAX_LEN};

// ============================================ Types =========================================== \\

pub(super) struct Read<Input, State, Buf = Vec<u8>> {
    inner: ReadInner<Input, State, Buf>,
}

enum ReadInner<Input, State, Buf> {
    Empty,
    Peek {
        msg: Buf,
        buf: Buf,
        inp: Input,
        state: State,
    },
    Advance {
        len: usize,
        off: usize,
        msg: Buf,
        buf: Buf,
        inp: Input,
        state: State,
    },
    Read {
        len: usize,
        off: usize,
        msg: Buf,
        buf: Buf,
        inp: Input,
        state: State,
    },
    Done {
        len: usize,
        msg: Buf,
        buf: Buf,
        inp: Input,
        state: State,
    },
}

// ========================================== impl Read ========================================= \\

impl<Input, State, Buf> Read<Input, State, Buf> {
    // ==================================== Constructors ==================================== \\

    #[inline]
    pub(super) fn new(msg: Buf, buf: Buf, inp: Input, state: State) -> Self
    where
        Input: AsyncPeek + AsyncRead + Unpin,
        State: NoiseState + Unpin,
        Buf: AsRef<[u8]> + AsMut<Vec<u8>> + Unpin,
    {
        Read {
            inner: ReadInner::Peek {
                msg,
                buf,
                inp,
                state,
            },
        }
    }

    // ===================================== Destructors ==================================== \\

    #[inline]
    pub(super) fn done(self) -> (Buf, Buf, Input, State) {
        match self.inner {
            ReadInner::Empty => panic!(),
            ReadInner::Peek {
                msg,
                buf,
                inp,
                state,
                ..
            }
            | ReadInner::Advance {
                msg,
                buf,
                inp,
                state,
                ..
            }
            | ReadInner::Read {
                msg,
                buf,
                inp,
                state,
                ..
            }
            | ReadInner::Done {
                msg,
                buf,
                inp,
                state,
                ..
            } => (msg, buf, inp, state),
        }
    }
}

// ========================================= impl Future ======================================== \\

impl<Input, State, Buf> Future for Read<Input, State, Buf>
where
    Input: AsyncPeek + AsyncRead + Unpin,
    State: NoiseState + Unpin,
    Buf: AsRef<[u8]> + AsMut<Vec<u8>> + Unpin,
{
    type Output = Result<usize>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        loop {
            match mem::take(inner) {
                ReadInner::Empty => panic!(),
                ReadInner::Peek {
                    msg,
                    mut buf,
                    mut inp,
                    state,
                } => match Pin::new(&mut inp).poll_peek(ctx, &mut buf.as_mut()[0..2]) {
                    Poll::Ready(Ok(2)) => {
                        let len = u16::from_le_bytes([buf.as_ref()[0], buf.as_ref()[1]]) as usize;

                        *inner = ReadInner::Advance {
                            len,
                            off: 0,
                            msg,
                            buf,
                            inp,
                            state,
                        };
                    }
                    Poll::Ready(Ok(_)) => panic!("peeked != 2"),
                    Poll::Ready(Err(err)) => {
                        *inner = ReadInner::Done {
                            len: 0,
                            msg,
                            buf,
                            inp,
                            state,
                        };

                        return Poll::Ready(Err(err.into()));
                    }
                    Poll::Pending => {
                        *inner = ReadInner::Peek {
                            msg,
                            buf,
                            inp,
                            state,
                        };

                        return Poll::Pending;
                    }
                },
                ReadInner::Advance {
                    len,
                    msg,
                    buf,
                    inp,
                    state,
                    ..
                } if len > RAW_MAX_LEN => {
                    *inner = ReadInner::Done {
                        len: 0,
                        msg,
                        buf,
                        inp,
                        state,
                    };

                    return Err(Error::MessageSize {
                        max: RAW_MAX_LEN,
                        actual: len,
                    })
                    .into();
                }
                ReadInner::Advance {
                    len,
                    off,
                    mut msg,
                    buf,
                    inp,
                    state,
                } if len - NOISE_OVERHEAD > msg.as_ref().len() => {
                    msg.as_mut().resize(len - NOISE_OVERHEAD, 0);

                    *inner = ReadInner::Advance {
                        len,
                        off,
                        msg,
                        buf,
                        inp,
                        state,
                    };
                }
                ReadInner::Advance {
                    len,
                    off,
                    msg,
                    mut buf,
                    inp,
                    state,
                } if len > buf.as_ref().len() => {
                    buf.as_mut().resize(len, 0);

                    *inner = ReadInner::Advance {
                        len,
                        off,
                        msg,
                        buf,
                        inp,
                        state,
                    };
                }
                ReadInner::Advance {
                    len,
                    off,
                    msg,
                    buf,
                    inp,
                    state,
                } if off >= 2 => {
                    *inner = ReadInner::Read {
                        len,
                        off: 0,
                        msg,
                        buf,
                        inp,
                        state,
                    };
                }
                ReadInner::Advance {
                    len,
                    mut off,
                    msg,
                    mut buf,
                    mut inp,
                    state,
                } => match Pin::new(&mut inp).poll_read(ctx, &mut buf.as_mut()[off..2]) {
                    Poll::Ready(Ok(read)) => {
                        off += read;

                        *inner = ReadInner::Advance {
                            len,
                            off,
                            msg,
                            buf,
                            inp,
                            state,
                        };
                    }
                    Poll::Ready(Err(err)) => {
                        *inner = ReadInner::Done {
                            len: 0,
                            msg,
                            buf,
                            inp,
                            state,
                        };

                        return Poll::Ready(Err(err.into()));
                    }
                    Poll::Pending => {
                        *inner = ReadInner::Advance {
                            len,
                            off,
                            msg,
                            buf,
                            inp,
                            state,
                        };

                        return Poll::Pending;
                    }
                },
                ReadInner::Read {
                    len,
                    off,
                    mut msg,
                    buf,
                    inp,
                    mut state,
                } if off >= len => match state.read_message(&buf.as_ref()[..len], msg.as_mut()) {
                    Ok(len) => {
                        *inner = ReadInner::Done {
                            len,
                            msg,
                            buf,
                            inp,
                            state,
                        };

                        return Poll::Ready(Ok(len));
                    }
                    Err(err) => {
                        *inner = ReadInner::Done {
                            len: 0,
                            msg,
                            buf,
                            inp,
                            state,
                        };

                        return Poll::Ready(Err(err));
                    }
                },
                ReadInner::Read {
                    len,
                    mut off,
                    msg,
                    mut buf,
                    mut inp,
                    state,
                } => match Pin::new(&mut inp).poll_read(ctx, &mut buf.as_mut()[off..len]) {
                    Poll::Ready(Ok(read)) => {
                        off += read;

                        *inner = ReadInner::Read {
                            len,
                            off,
                            msg,
                            buf,
                            inp,
                            state,
                        };
                    }
                    Poll::Ready(Err(err)) => {
                        *inner = ReadInner::Done {
                            len: 0,
                            msg,
                            buf,
                            inp,
                            state,
                        };

                        return Poll::Ready(Err(err.into()));
                    }
                    Poll::Pending => {
                        *inner = ReadInner::Read {
                            len,
                            off,
                            msg,
                            buf,
                            inp,
                            state,
                        };

                        return Poll::Pending;
                    }
                },
                ReadInner::Done {
                    len,
                    msg,
                    buf,
                    inp,
                    state,
                } => {
                    *inner = ReadInner::Done {
                        len,
                        msg,
                        buf,
                        inp,
                        state,
                    };

                    return Poll::Ready(Ok(len));
                }
            }
        }
    }
}

// ======================================== impl Default ======================================== \\

impl<Input, State, Buf> Default for ReadInner<Input, State, Buf> {
    #[inline]
    fn default() -> Self {
        ReadInner::Empty
    }
}

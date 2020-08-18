/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use async_peek::AsyncPeekExt;
use pr070c01::{packets, Error, Handshake, Protocol};
use smol::{Async, Task};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

// ======================================= #[test] hello() ====================================== \\

#[test]
fn hello() -> Result<(), Error> {
    smol::run(ahello())
}

async fn ahello() -> Result<(), Error> {
    let addr = "127.0.0.1:0".to_socket_addrs()?.next().unwrap();
    let listener = Async::<TcpListener>::bind(addr)?;

    let addr = listener.get_ref().local_addr()?;

    let initiate = Task::spawn(async move {
        let mut stream = Async::<TcpStream>::connect(addr).await?;

        Result::<_, Error>::Ok((initiate(&stream).await?, stream))
    });

    let respond = Task::spawn(async move {
        let (mut stream, _) = listener.accept().await?;

        Result::<_, Error>::Ok((respond(&stream).await?, stream, listener))
    });

    let (initiator, responder) = ufut::zip(initiate, respond).await;
    let (mut pinit, mut sinit) = initiator?;
    let (mut presp, mut sresp, _listener) = responder?;

    pinit.send(&sinit, packets::Heartbeat).await?;
    let packet = presp.try_recv::<_, packets::Heartbeat>(&sresp).await?;
    dbg!(packet);

    presp.send(&sresp, packets::Heartbeat).await?;
    let packet = pinit.try_recv::<_, packets::Heartbeat>(&sinit).await?;
    dbg!(packet);

    Ok(())
}

async fn initiate(stream: &Async<TcpStream>) -> Result<Protocol, Error> {
    Ok(Handshake::initiate(stream, stream).await?.done())
}

async fn respond(stream: &Async<TcpStream>) -> Result<Protocol, Error> {
    Ok(Handshake::respond(stream, stream).await?.done())
}

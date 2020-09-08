/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use async_net::{TcpListener, TcpStream};
use futures_lite::future;
use pr070c01::{Handshake, Packet, Result};

// ======================================= #[test] hello() ====================================== \\

#[test]
fn hello() -> Result<()> {
    smol::block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let initiate = smol::spawn(async move {
            let stream = TcpStream::connect(addr).await?;
            let proto = Handshake::initiate(&stream).await?.done()?;

            Result::Ok((stream, proto))
        });

        let respond = smol::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let proto = Handshake::respond(&stream).await?.done()?;

            Result::Ok((stream, proto))
        });

        let ((istream, mut iproto), (rstream, mut rproto)) =
            future::try_zip(initiate, respond).await?;

        iproto.send(&istream, Packet::heartbeat()).await?;
        assert!(rproto.recv(&rstream).await?.is_heartbeat());

        rproto.send(&rstream, Packet::heartbeat()).await?;
        assert!(iproto.recv(&istream).await?.is_heartbeat());

        Ok(())
    })
}

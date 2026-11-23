//! Connection-wide requests and ordered replies (RFC 4254 §4).
use super::{
    Bytes, Connection, Event, KEEPALIVE_REQUEST, MAX_FIELDS, MAX_REQUESTS, input, named_size,
    packet,
};
use crate::{auth::malformed, clear_packet::invalid, wire::Reader};
use std::{collections::VecDeque, io};
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) const REQUEST: u8 = 80;
pub(crate) const SUCCESS: u8 = 81;
pub(crate) const FAILURE: u8 = 82;

pub(crate) fn request_packet(name: &str, want_reply: bool, fields: &[u8]) -> io::Result<Vec<u8>> {
    let size = named_size(6, name, fields)?;
    packet(size, |writer| {
        writer.byte(REQUEST)?;
        writer.string(name.as_bytes())?;
        writer.boolean(want_reply)?;
        writer.fixed(fields)
    })
}

/// A connection-local token for a global request that requires a reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalRequestId(u64);

/// An inbound global request. Its payload is defined by the request name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalRequest {
    pub name: Bytes,
    pub fields: Bytes,
    pub reply_id: Option<GlobalRequestId>,
}

impl GlobalRequest {
    pub fn wants_reply(&self) -> bool {
        self.reply_id.is_some()
    }
}

/// The peer either refuses the request or returns request-specific data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GlobalReply {
    Success(Bytes),
    Failure,
}

#[derive(Default)]
pub(super) struct Requests {
    enabled: bool,
    incoming: VecDeque<PendingReply>,
    next_id: u64,
    pub(super) outgoing: usize,
}

#[derive(PartialEq, Eq)]
enum PendingReply {
    Application(GlobalRequestId),
    Automatic(bool),
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// Deliver inbound global requests as events. By default low-level
    /// connections automatically refuse requests that ask for a reply.
    pub fn enable_global_requests(&mut self) {
        self.global.enabled = true;
    }

    /// Send a global request. A reply, if requested, arrives as an event.
    pub async fn global_request(
        &mut self,
        name: &str,
        want_reply: bool,
        fields: &[u8],
    ) -> io::Result<()> {
        let payload = request_packet(name, want_reply, fields)?;
        if want_reply && self.global.outgoing == MAX_REQUESTS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many outstanding SSH global requests",
            ));
        }
        if name == KEEPALIVE_REQUEST && fields.is_empty() {
            self.check()?;
            self.connection.transport.send_probe(&payload).await?;
        } else {
            self.send(&payload).await?;
        }
        self.global.outgoing += usize::from(want_reply);
        Ok(())
    }

    /// Reply to the oldest outstanding inbound global request.
    pub async fn global_reply(
        &mut self,
        id: GlobalRequestId,
        reply: GlobalReply,
    ) -> io::Result<()> {
        if self.global.incoming.front() != Some(&PendingReply::Application(id)) {
            return Err(input("SSH global replies must follow request order"));
        }
        match reply {
            GlobalReply::Failure => self.send(&[FAILURE]).await?,
            GlobalReply::Success(fields) => {
                if fields.len() > MAX_FIELDS {
                    return Err(input("oversized SSH global reply"));
                }
                self.send(&packet(1 + fields.len(), |writer| {
                    writer.byte(SUCCESS)?;
                    writer.fixed(&fields)
                })?)
                .await?;
            }
        }
        self.global.incoming.pop_front();
        self.flush_automatic_replies().await
    }

    async fn flush_automatic_replies(&mut self) -> io::Result<()> {
        while let Some(PendingReply::Automatic(success)) = self.global.incoming.front() {
            self.send(&[if *success { SUCCESS } else { FAILURE }])
                .await?;
            self.global.incoming.pop_front();
        }
        Ok(())
    }

    pub(super) async fn receive_global_request(
        &mut self,
        mut reader: Reader<'_>,
    ) -> io::Result<Option<Event>> {
        let name = reader.string().map_err(malformed)?;
        let want_reply = reader.boolean().map_err(malformed)?;
        let fields = reader.remaining();
        if !self.global.enabled {
            if want_reply {
                self.send(&[FAILURE]).await?;
            }
            return Ok(None);
        }
        if name.len().saturating_add(fields.len()) > MAX_FIELDS {
            return Err(invalid("oversized SSH global request"));
        }
        if want_reply && self.global.incoming.len() == MAX_REQUESTS {
            return Err(invalid("too many pending SSH global requests"));
        }
        let automatic = if name == KEEPALIVE_REQUEST.as_bytes() && fields.is_empty() {
            Some(true)
        } else if self
            .connection
            .permissions
            .as_ref()
            .is_some_and(|policy| !policy.allows_global(name))
        {
            Some(false)
        } else {
            None
        };
        if let Some(success) = automatic {
            if want_reply {
                self.global
                    .incoming
                    .push_back(PendingReply::Automatic(success));
                self.flush_automatic_replies().await?;
            }
            return Ok(None);
        }
        let reply_id = if want_reply {
            let id = GlobalRequestId(self.global.next_id);
            self.global.next_id = self
                .global
                .next_id
                .checked_add(1)
                .ok_or_else(|| invalid("SSH global request IDs exhausted"))?;
            self.global
                .incoming
                .push_back(PendingReply::Application(id));
            Some(id)
        } else {
            None
        };
        Ok(Some(Event::GlobalRequest(GlobalRequest {
            name: Bytes::copy_from_slice(name),
            fields: Bytes::copy_from_slice(fields),
            reply_id,
        })))
    }

    pub(super) fn receive_global_reply(
        &mut self,
        message: u8,
        reader: Reader<'_>,
    ) -> io::Result<Option<Event>> {
        if self.global.outgoing == 0 {
            return Err(invalid("unsolicited SSH global reply"));
        }
        let reply = if message == SUCCESS {
            let fields = reader.remaining();
            if fields.len() > MAX_FIELDS {
                return Err(invalid("oversized SSH global reply"));
            }
            GlobalReply::Success(Bytes::copy_from_slice(fields))
        } else {
            reader.finish().map_err(malformed)?;
            GlobalReply::Failure
        };
        self.global.outgoing -= 1;
        Ok(Some(Event::GlobalReply(reply)))
    }
}

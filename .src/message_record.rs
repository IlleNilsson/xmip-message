//! A Message's one binary form: what the Ledger keeps of it, as the body of
//! Xmip Storage's Message record (`runtime-model.md` section 3, *The
//! Ledger*: *Stream written to the Ledger, in chunks; Message record
//! created, referencing that Stream*), and the Message read back from it.
//!
//! **The Message, not its content.** A Section's Stream is in the Ledger
//! already, in chunks, under its own identifier, and a Stream is never
//! copied: the record keeps the Stream's identifier, its length and its
//! media type, and a record read back holds each Stream kept where its
//! caller reads it from — the Ledger's chunks — never whole. What the Message accumulates — its lineage, its treatment, its
//! Context — is written whole.
//!
//! **Binary, not JSON.** The record is written for every Message and read
//! by the next step's thread, so the fields are written in their order — no
//! names, no padding: identifiers as 16 bytes big-endian, a count, a length
//! or a generation as a varint, text as its length and its UTF-8 bytes, an
//! absent value as one byte saying so, each enumeration as its number. JSON
//! would spend bytes on names and time on a text parser at every hand-on,
//! and the estate keeps no JSON at rest (ADR-0031 clause 3). The first byte
//! is the form's number, [`FORM`], so a form that follows can still read
//! what this one wrote. A Context value is its kind's number and the value:
//! a boolean as a byte, an integer as 8 bytes big-endian, a decimal as its
//! IEEE 754 bits, text and bytes counted.
//!
//! One form, here, with the type it writes: Xmip Storage keeps the body as
//! it is given, byte for byte, and nothing else writes a Message's.

use codec::CodecError;
use codec::cursor::Cursor;
use codec::field::{
    counted, many, optional, place, placed, read_counted, read_many, read_optional, read_text, text,
};
use codec::writer::ByteWriter;
use context::MessageContext;
use std::sync::Arc;
use stream::{Content, Stream};
use xcore::{MessageId, ScalarValue, SectionId, StreamId};

use crate::{
    ExecutionProfile, Message, MessageCreationSource, MessageDurability, MessagePriority,
    MessageSection, MessageTreatment,
};

/// The form's number, the first byte of every record written in it.
pub const FORM: u8 = 1;

impl MessageCreationSource {
    /// Its number in the Message's one binary form: what Xmip Storage's
    /// `message.created_by` column keeps, numbered once.
    #[must_use]
    pub fn number(self) -> u8 {
        place(&SOURCES, &self)
    }
}

impl MessagePriority {
    /// Its number in the Message's one binary form: what Xmip Storage's
    /// `message.priority` column keeps, numbered once.
    #[must_use]
    pub fn number(self) -> u8 {
        place(&PRIORITIES, &self)
    }
}

impl ExecutionProfile {
    /// Its number in the Message's one binary form: what Xmip Storage's
    /// `message.execution_profile` column keeps, numbered once.
    #[must_use]
    pub fn number(self) -> u8 {
        place(&PROFILES, &self)
    }
}

impl MessageDurability {
    /// Its number in the Message's one binary form: what Xmip Storage's
    /// `message.durability` column keeps, numbered once.
    #[must_use]
    pub fn number(self) -> u8 {
        place(&DURABILITIES, &self)
    }
}

// Every value of each kind, in the order the form numbers them, which only
// grows at its end.
const SOURCES: [MessageCreationSource; 4] = [
    MessageCreationSource::Receive,
    MessageCreationSource::Assignment,
    MessageCreationSource::Transformation,
    MessageCreationSource::SendPreparation,
];
const PRIORITIES: [MessagePriority; 5] = [
    MessagePriority::Immediate,
    MessagePriority::High,
    MessagePriority::Normal,
    MessagePriority::Low,
    MessagePriority::Background,
];
const PROFILES: [ExecutionProfile; 3] = [
    ExecutionProfile::Conversation,
    ExecutionProfile::Business,
    ExecutionProfile::PassThrough,
];
const DURABILITIES: [MessageDurability; 3] = [
    MessageDurability::Ephemeral,
    MessageDurability::Durable,
    MessageDurability::Recoverable,
];

impl Message {
    /// The Message in its one binary form: everything but its Sections'
    /// content, which each Section names by its Stream's identifier.
    #[must_use]
    pub fn record(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + 48 * self.context.iter().count());
        out.byte(FORM).u128_be(self.message_id.value());
        optional(&mut out, self.previous_message_id, |out, id| {
            out.u128_be(id.value());
        });
        out.varint(u64::from(self.generation));
        out.byte(place(&SOURCES, &self.created_by))
            .byte(place(&PRIORITIES, &self.treatment.priority))
            .byte(place(&PROFILES, &self.treatment.execution_profile))
            .byte(place(&DURABILITIES, &self.treatment.durability));
        many(&mut out, &self.sections, |out, section| {
            out.u128_be(section.section_id.value());
            optional(out, section.name.as_deref(), text);
            out.u128_be(section.stream.id().value())
                .varint(section.stream.len() as u64);
            optional(out, section.stream.media_type(), text);
            optional(out, section.contract.as_deref(), text);
        });
        let context: Vec<(&str, &ScalarValue)> = self.context.iter().collect();
        many(&mut out, &context, |out, (name, value)| {
            text(out, name);
            scalar(out, value);
        });
        out
    }

    /// The Message `bytes` hold in its one binary form, and nothing after
    /// it, each Section's Stream kept ([`Stream::kept`]) where `content`
    /// says its identifier's bytes are read from — the Ledger's chunks,
    /// which this crate does not reach — at the length recorded, which
    /// `content` is told, so it can hold what it reads to it.
    ///
    /// # Errors
    ///
    /// Where the bytes are not one — another form, a field cut short, a
    /// number naming nothing, text that is not UTF-8, bytes after it — or
    /// `content` failed.
    pub fn from_record(
        bytes: &[u8],
        mut content: impl FnMut(StreamId, u64) -> Result<Arc<dyn Content>, CodecError>,
    ) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(bytes);
        let form = cursor.byte()?;
        if form != FORM {
            return Err(CodecError::new(format!(
                "a Message record of form {form}, and this reads form {FORM}"
            )));
        }
        let message_id = MessageId::new(cursor.u128_be()?);
        let previous_message_id = read_optional(&mut cursor, |c| Ok(MessageId::new(c.u128_be()?)))?;
        let generation = u32::try_from(cursor.varint()?)
            .map_err(|_| CodecError::new("a Message's generation past u32"))?;
        let created_by = placed(&SOURCES, cursor.byte()?, "Message creation source")?;
        let treatment = MessageTreatment {
            priority: placed(&PRIORITIES, cursor.byte()?, "Message priority")?,
            execution_profile: placed(&PROFILES, cursor.byte()?, "execution profile")?,
            durability: placed(&DURABILITIES, cursor.byte()?, "Message durability")?,
        };
        let sections = read_many(&mut cursor, |c| {
            let section_id = SectionId::new(c.u128_be()?);
            let name = read_optional(c, read_text)?;
            let stream = StreamId::new(c.u128_be()?);
            let length = c.varint()?;
            let media_type = read_optional(c, read_text)?;
            let contract = read_optional(c, read_text)?;
            Ok(MessageSection {
                section_id,
                name,
                stream: Stream::kept(stream, length, media_type, content(stream, length)?),
                contract,
            })
        })?;
        let context = read_many(&mut cursor, |c| Ok((read_text(c)?, read_scalar(c)?)))?
            .into_iter()
            .fold(MessageContext::new(), |context, (name, value)| {
                context.with_value(name, value)
            });
        if !cursor.is_empty() {
            return Err(CodecError::new("bytes after the Message record"));
        }
        Ok(Self {
            message_id,
            previous_message_id,
            generation,
            created_by,
            treatment,
            sections: Arc::from(sections),
            context: Arc::new(context),
        })
    }
}

/// A Context value: its kind's number, then the value.
fn scalar(out: &mut Vec<u8>, value: &ScalarValue) {
    match value {
        ScalarValue::Null => {
            out.byte(0);
        }
        ScalarValue::Bool(yes) => {
            out.byte(1).byte(u8::from(*yes));
        }
        ScalarValue::Integer(integer) => {
            out.byte(2).i64_be(*integer);
        }
        ScalarValue::Decimal(decimal) => {
            out.byte(3).u64_be(decimal.to_bits());
        }
        ScalarValue::Text(value) => {
            out.byte(4);
            text(out, value);
        }
        ScalarValue::Binary(bytes) => {
            counted(out.byte(5), bytes);
        }
    }
}

fn read_scalar(cursor: &mut Cursor<'_>) -> Result<ScalarValue, CodecError> {
    Ok(match cursor.byte()? {
        0 => ScalarValue::Null,
        1 => ScalarValue::Bool(cursor.byte()? != 0),
        2 => ScalarValue::Integer(cursor.i64_be()?),
        3 => ScalarValue::Decimal(f64::from_bits(cursor.u64_be()?)),
        4 => ScalarValue::Text(read_text(cursor)?),
        5 => ScalarValue::Binary(read_counted(cursor)?.to_vec()),
        other => {
            return Err(CodecError::new(format!(
                "no Context value kind is numbered {other}"
            )));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> MessageContext {
        MessageContext::new()
            .with_value(
                "xmip.transport.mechanism",
                ScalarValue::Text("circumstance".into()),
            )
            .with_value("xmip.transport.proven", ScalarValue::Bool(false))
            .with_value("Amount", ScalarValue::Integer(-1200))
            .with_value("Rate", ScalarValue::Decimal(0.25))
            .with_value("Nothing", ScalarValue::Null)
            .with_value("Raw", ScalarValue::Binary(vec![0, 255]))
    }

    fn received() -> Message {
        let section = MessageSection {
            section_id: SectionId::new(2),
            name: Some("body".to_string()),
            stream: Stream::new(
                StreamId::new(3),
                b"<Order/>".to_vec(),
                Some("application/xml".into()),
            ),
            contract: Some("xmip-core-contract-xml".to_string()),
        };
        Message::received(
            MessageId::new(1),
            vec![section],
            context(),
            MessageTreatment::PASS_THROUGH,
        )
    }

    /// Content in memory, as the Ledger would read it back.
    struct Kept(&'static [u8]);

    impl Content for Kept {
        fn reader(&self) -> std::io::Result<Box<dyn std::io::Read + Send + '_>> {
            Ok(Box::new(self.0))
        }
    }

    /// Where the one Stream the tests keep is read from.
    fn ledger(stream: StreamId, length: u64) -> Result<Arc<dyn Content>, CodecError> {
        assert_eq!((stream, length), (StreamId::new(3), 8));
        Ok(Arc::new(Kept(b"<Order/>")))
    }

    #[test]
    fn a_message_comes_back_from_its_record_as_it_was() {
        let first = received();
        let assigned = first.assigned(MessageId::new(4), context());
        for message in [first, assigned] {
            let record = message.record();
            assert_eq!(record[0], FORM);
            assert_eq!(
                Message::from_record(&record, ledger).expect("read"),
                message
            );
        }
    }

    #[test]
    fn the_record_keeps_the_stream_by_its_identifier_not_its_bytes() {
        let section = MessageSection {
            stream: Stream::new(StreamId::new(3), vec![b'x'; 100_000], None),
            ..received().sections()[0].clone()
        };
        let large = Message::received(
            MessageId::new(1),
            vec![section],
            context(),
            MessageTreatment::BUSINESS,
        );
        assert!(large.record().len() < 400, "{}", large.record().len());
        let read = Message::from_record(&large.record(), |_, _| {
            Ok(Arc::new(Kept(b"xxxxxxxxx")) as Arc<dyn Content>)
        })
        .expect("a record keeps no content to check");
        let stream = &read.sections()[0].stream;
        assert_eq!(stream.len(), 100_000, "the length recorded, nothing read");
        let refused = stream.load().expect_err("a Stream of another length");
        assert!(
            refused.to_string().contains("100000 were kept"),
            "{refused}"
        );
    }

    #[test]
    fn bytes_that_are_not_a_record_are_refused() {
        let record = received().record();
        for cut in [0, 1, 17, record.len() - 1] {
            assert!(
                Message::from_record(&record[..cut], ledger).is_err(),
                "{cut}"
            );
        }
        let longer = [record.as_slice(), &[0]].concat();
        assert!(Message::from_record(&longer, ledger).is_err());
        let mut other_form = record;
        other_form[0] = FORM + 1;
        assert!(Message::from_record(&other_form, ledger).is_err());
    }
}

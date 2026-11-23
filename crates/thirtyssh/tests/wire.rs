use thirtyssh::wire::{Error, Reader, Writer};

#[test]
fn scalar_fields_match_network_order() {
    let expected = [0xff, 0, 1, 1, 2, 3, 4, 0x80, 0, 0, 0, 0, 0, 0, 1];
    let mut output = [0; 15];
    let mut writer = Writer::new(&mut output);
    writer.byte(0xff).unwrap();
    writer.boolean(false).unwrap();
    writer.boolean(true).unwrap();
    writer.uint32(0x01020304).unwrap();
    writer.uint64(0x8000000000000001).unwrap();
    assert_eq!(writer.written(), expected);
    let mut reader = Reader::new(&expected);
    assert!(reader.boolean().unwrap()); // All nonzero wire values denote true.
    assert!(!reader.boolean().unwrap());
    assert!(reader.boolean().unwrap());
    assert_eq!(reader.uint32().unwrap(), 0x01020304);
    assert_eq!(reader.uint64().unwrap(), 0x8000000000000001);
    reader.finish().unwrap();
}

#[test]
fn rfc_mpints_preserve_sign_and_zero() {
    for field in [
        &b"\0\0\0\0"[..],
        b"\0\0\0\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7",
        b"\0\0\0\x02\0\x80",
        b"\0\0\0\x02\xff\x7f",
        b"\0\0\0\x02\xed\xcc",
        b"\0\0\0\x05\xff\x21\x52\x41\x11",
        b"\0\0\0\x01\xff",
    ] {
        let mut output = [0; 12];
        let mut writer = Writer::new(&mut output);
        writer.mpint(&field[4..]).unwrap();
        assert_eq!(writer.written(), field);
        assert_eq!(Reader::new(field).mpint().unwrap(), &field[4..]);
    }
}

#[test]
fn malformed_fields_leave_the_cursor_unchanged() {
    for field in [
        &b"\0\0\0\x01\0"[..],
        b"\0\0\0\x02\0\x7f",
        b"\0\0\0\x02\xff\x80",
    ] {
        let mut reader = Reader::new(field);
        assert_eq!(reader.mpint(), Err(Error::InvalidMpint));
        assert_eq!(reader.remaining(), field);
        let mut out = [0; 6];
        let mut writer = Writer::new(&mut out);
        assert_eq!(writer.mpint(&field[4..]), Err(Error::InvalidMpint));
        assert!(writer.written().is_empty());
    }
    for text in [&b"ab,"[..], b",ab", b"a,,b", b"x\0", b"\xff"] {
        let mut field = [0; 16];
        let mut writer = Writer::new(&mut field);
        writer.string(text).unwrap();
        let mut reader = Reader::new(writer.written());
        assert_eq!(reader.name_list(), Err(Error::InvalidNameList));
        assert_eq!(reader.remaining(), writer.written());
    }
}

#[test]
fn bounded_buffers_and_truncated_strings() {
    let field = b"\0\0\0\x03\xff\0a";
    for end in 0..field.len() {
        let mut reader = Reader::new(&field[..end]);
        assert_eq!(reader.string(), Err(Error::Truncated));
        assert_eq!(reader.remaining(), &field[..end]);
        let mut output = [0xaa; 7];
        let mut writer = Writer::new(&mut output[..end]);
        assert_eq!(writer.string(&field[4..]), Err(Error::OutputTooSmall));
        assert!(writer.written().is_empty());
        assert_eq!(output, [0xaa; 7]);
    }
    assert_eq!(Reader::new(field).string().unwrap(), &field[4..]);
    assert_eq!(Reader::new(&[255; 4]).string(), Err(Error::Truncated));
    assert_eq!(Reader::new(&[1]).finish(), Err(Error::TrailingBytes));
    let mut output = [0; 18];
    let mut writer = Writer::new(&mut output);
    writer.name_list("").unwrap();
    assert_eq!(writer.name_list("a,,b"), Err(Error::InvalidNameList));
    writer.name_list("zlib,none").unwrap();
    let mut reader = Reader::new(writer.written());
    assert_eq!(reader.name_list().unwrap(), "");
    assert_eq!(reader.name_list().unwrap(), "zlib,none");
    reader.finish().unwrap();
}

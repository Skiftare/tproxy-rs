use tproxy_rs::frame::decode_batch;

#[test]
fn hello_batch() {
    let buf = vec![0x10u8, 0, 0, 0, 0, 0, 0, 1, 0x01];
    match decode_batch(&buf) {
        Ok(frames) => {
            assert_eq!(frames.len(), 1, "должен быть 1 фрейм");
            assert_eq!(frames[0].ty, 0x10, "тип HELLO");
            assert_eq!(frames[0].payload, vec![0x01]);
        }
        Err(e) => panic!("decode_batch error: {e:?}"),
    }
}

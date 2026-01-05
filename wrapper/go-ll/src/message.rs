// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use serde::{de::DeserializeOwned, Serialize};

use crate::ByteBuffer;

pub trait MessageRouting {
    fn src_party_id(&self) -> u8;
    fn dst_party_id(&self) -> Option<u8>;
}

#[repr(C)]
pub struct Message {
    pub from_id: u8,
    pub to_id: u8, // 255 means None
    pub payload: ByteBuffer,
}

impl Message {
    pub fn new<T: Serialize + MessageRouting>(payload: T) -> Self {
        let mut buffer = vec![];
        ciborium::into_writer(&payload, &mut buffer)
            .expect("CBOR encode error");

        let from_id = payload.src_party_id();
        let to_id = payload.dst_party_id().unwrap_or(255);

        Message {
            from_id,
            to_id,
            payload: ByteBuffer::from_vec(buffer),
        }
    }

    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, String> {
        let buffer = unsafe {
            std::slice::from_raw_parts(
                self.payload.data,
                self.payload.len,
            )
        };
        let buffer_copy = buffer.to_vec();
        ciborium::from_reader::<T, _>(buffer_copy.as_slice())
            .map_err(|e| format!("CBOR decode error: {}", e))
    }

    pub fn decode_vector<T: DeserializeOwned>(
        input: &[Message],
    ) -> Result<Vec<T>, String> {
        input.iter().map(|msg| msg.decode()).collect()
    }

    pub fn encode_vector<T: Serialize + MessageRouting>(
        msgs: Vec<T>,
    ) -> Vec<Message> {
        msgs.into_iter().map(|msg| Message::new(msg)).collect()
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_message_free(msg: *mut Message) {
    if msg.is_null() {
        return;
    }
    let mut msg = Box::from_raw(msg);
    let payload = std::mem::replace(&mut msg.payload, ByteBuffer {
        data: ptr::null_mut(),
        len: 0,
        cap: 0,
    });
    dkls_free_bytes(payload);
}

#[no_mangle]
pub unsafe extern "C" fn dkls_message_free_array(
    msgs: *mut Message,
    len: usize,
) {
    if msgs.is_null() {
        return;
    }
    let slice = std::slice::from_raw_parts_mut(msgs, len);
    for msg in slice {
        let payload = std::mem::replace(&mut msg.payload, ByteBuffer {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        });
        dkls_free_bytes(payload);
    }
    let _ = Vec::from_raw_parts(msgs, len, len);
}

use crate::dkls_free_bytes;
use std::ptr;

#[repr(C)]
pub struct MessageArray {
    pub msgs: *mut Message,
    pub len: usize,
}

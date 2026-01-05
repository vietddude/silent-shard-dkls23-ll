// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(clippy::missing_safety_doc)]

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::ptr;

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

mod errors;
mod keygen;
mod keyshare;
mod message;
mod sign;
mod sign_ot_variant;
mod utils;

pub use keygen::KeygenSessionHandle;
pub use keyshare::KeyshareHandle;
pub use message::{Message, MessageArray};
pub use sign::SignSessionHandle;
pub use sign_ot_variant::SignSessionOTVariantHandle;

pub fn maybe_seeded_rng(seed: Option<&[u8]>) -> ChaCha20Rng {
    let seed = match seed {
        None => rand::thread_rng().gen(),
        Some(seed) => {
            seed.try_into().expect("invalid seed size")
        }
    };

    ChaCha20Rng::from_seed(seed)
}

// Error handling
#[repr(C)]
pub struct GoError {
    message: *mut c_char,
    code: c_int,
}

impl GoError {
    fn new(msg: &str, code: c_int) -> Self {
        let c_str = CString::new(msg).unwrap();
        GoError {
            message: c_str.into_raw(),
            code,
        }
    }

}

#[no_mangle]
pub unsafe extern "C" fn dkls_free_error(err: *mut GoError) {
    if err.is_null() {
        return;
    }
    if !(*err).message.is_null() {
        let _ = CString::from_raw((*err).message);
    }
    let _ = Box::from_raw(err);
}

#[no_mangle]
pub unsafe extern "C" fn dkls_error_message(err: *const GoError) -> *const c_char {
    if err.is_null() || (*err).message.is_null() {
        return ptr::null();
    }
    (*err).message
}

#[no_mangle]
pub unsafe extern "C" fn dkls_error_code(err: *const GoError) -> c_int {
    if err.is_null() {
        return -1;
    }
    (*err).code
}

// Byte buffer helpers
#[repr(C)]
pub struct ByteBuffer {
    data: *mut u8,
    len: usize,
    cap: usize,
}

impl ByteBuffer {
    fn from_vec(vec: Vec<u8>) -> Self {
        let mut vec = vec;
        vec.shrink_to_fit();
        let data = vec.as_mut_ptr();
        let len = vec.len();
        let cap = vec.capacity();
        std::mem::forget(vec);
        ByteBuffer { data, len, cap }
    }

}

#[no_mangle]
pub unsafe extern "C" fn dkls_free_bytes(buf: ByteBuffer) {
    if buf.data.is_null() {
        return;
    }
    let _ = Vec::from_raw_parts(buf.data, buf.len, buf.cap);
}

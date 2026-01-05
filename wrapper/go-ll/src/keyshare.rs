// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::os::raw::{c_int, c_uchar};
use std::ptr;

use k256::elliptic_curve::group::GroupEncoding;

use dkls23_ll::dkg;

use crate::ByteBuffer;
use std::slice;

#[repr(C)]
pub struct KeyshareHandle {
    pub(crate) inner: dkg::Keyshare,
}

impl KeyshareHandle {
    pub(crate) fn new(inner: dkg::Keyshare) -> Self {
        Self { inner }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keyshare_from_bytes(
    bytes: *const u8,
    len: usize,
) -> *mut KeyshareHandle {
    let slice = slice::from_raw_parts(bytes, len);
    match ciborium::from_reader::<dkg::Keyshare, _>(slice) {
        Ok(keyshare) => Box::into_raw(Box::new(KeyshareHandle::new(keyshare))),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keyshare_to_bytes(
    handle: *const KeyshareHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
    }

    let mut buffer = vec![];
    if ciborium::into_writer(&(*handle).inner, &mut buffer).is_err() {
        return ByteBuffer {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
    }

    ByteBuffer::from_vec(buffer)
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keyshare_public_key(
    handle: *const KeyshareHandle,
    out: *mut u8,
) -> c_int {
    if handle.is_null() || out.is_null() {
        return -1;
    }

    let bytes = (*handle).inner.public_key.to_bytes();
    let bytes_slice: &[u8] = bytes.as_ref();
    if bytes_slice.len() != 33 {
        return -1;
    }

    ptr::copy_nonoverlapping(bytes_slice.as_ptr(), out, 33);
    0
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keyshare_participants(
    handle: *const KeyshareHandle,
) -> c_uchar {
    if handle.is_null() {
        return 0;
    }
    (*handle).inner.rank_list.len() as c_uchar
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keyshare_threshold(
    handle: *const KeyshareHandle,
) -> c_uchar {
    if handle.is_null() {
        return 0;
    }
    (*handle).inner.threshold
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keyshare_party_id(
    handle: *const KeyshareHandle,
) -> c_uchar {
    if handle.is_null() {
        return 0;
    }
    (*handle).inner.party_id
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keyshare_free(handle: *mut KeyshareHandle) {
    if handle.is_null() {
        return;
    }
    let _ = Box::from_raw(handle);
}


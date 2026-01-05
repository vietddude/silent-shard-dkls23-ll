// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::os::raw::{c_char, c_int};
use std::ptr;

use derivation_path::DerivationPath;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use dkls23_ll::dsg;

use crate::{
    errors::sign_error_to_go,
    keyshare::KeyshareHandle,
    maybe_seeded_rng,
    message::{Message, MessageRouting},
    utils::c_str_to_string,
    ByteBuffer, GoError,
};

#[derive(Serialize, Deserialize)]
enum Round {
    Init,
    WaitMsg1,
    WaitMsg2,
    WaitMsg3,
    Pre(dsg::PreSignature),
    WaitMsg4(dsg::PartialSignature),
    Failed,
    Finished,
}

// Note: PreSignature and PartialSignature don't implement Clone
// We'll handle serialization differently - only serialize when in a serializable state

#[repr(C)]
pub struct SignSessionHandle {
    state: dsg::State,
    round: Round,
}

impl SignSessionHandle {
    fn new(state: dsg::State) -> Self {
        Self {
            state,
            round: Round::Init,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_sign_new(
    keyshare: *const KeyshareHandle,
    chain_path: *const c_char,
    seed: *const u8,
    seed_len: usize,
    err_out: *mut *mut GoError,
) -> *mut SignSessionHandle {
    if keyshare.is_null() {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("null keyshare", 1)));
        }
        return ptr::null_mut();
    }

    let chain_path_str = match c_str_to_string(chain_path) {
        Ok(s) => s,
        Err(e) => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new(&e, 1)));
            }
            return ptr::null_mut();
        }
    };

    let chain_path = match DerivationPath::from_str(&chain_path_str) {
        Ok(p) => p,
        Err(_) => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("invalid derivation path", 1)));
            }
            return ptr::null_mut();
        }
    };

    let seed = if seed.is_null() || seed_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(seed, seed_len))
    };

    let mut rng = maybe_seeded_rng(seed);

    match dsg::State::new(&mut rng, (*keyshare).inner.clone(), &chain_path) {
        Ok(state) => Box::into_raw(Box::new(SignSessionHandle::new(state))),
        Err(_e) => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("sign session init failed", 1)));
            }
            ptr::null_mut()
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SignSessionSerializable {
    round: Round,
}

#[no_mangle]
pub unsafe extern "C" fn dkls_sign_to_bytes(
    handle: *const SignSessionHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
    }

    // Note: State cannot be serialized, and Pre/PartialSignature don't implement Clone
    // We can only serialize when not in Pre or WaitMsg4 states
    let round = match &(*handle).round {
        Round::Init => Round::Init,
        Round::WaitMsg1 => Round::WaitMsg1,
        Round::WaitMsg2 => Round::WaitMsg2,
        Round::WaitMsg3 => Round::WaitMsg3,
        Round::Pre(_) => return ByteBuffer { data: ptr::null_mut(), len: 0, cap: 0 }, // Cannot serialize Pre state
        Round::WaitMsg4(_) => return ByteBuffer { data: ptr::null_mut(), len: 0, cap: 0 }, // Cannot serialize WaitMsg4 state
        Round::Failed => Round::Failed,
        Round::Finished => Round::Finished,
    };
    let serializable = SignSessionSerializable { round };

    let mut buffer = vec![];
    if ciborium::into_writer(&serializable, &mut buffer).is_err() {
        return ByteBuffer {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
    }

    ByteBuffer::from_vec(buffer)
}

#[no_mangle]
pub unsafe extern "C" fn dkls_sign_from_bytes(
    _bytes: *const u8,
    _len: usize,
) -> *mut SignSessionHandle {
    // Note: We cannot fully deserialize because State is not serializable
    // This function is provided for API compatibility but will return null
    // In practice, sessions should be kept in memory and not serialized mid-protocol
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn dkls_sign_create_first_message(
    handle: *mut SignSessionHandle,
    err_out: *mut *mut GoError,
) -> *mut Message {
    if handle.is_null() {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("null handle", 1)));
        }
        return ptr::null_mut();
    }

    match (*handle).round {
        Round::Init => {
            (*handle).round = Round::WaitMsg1;
            Box::into_raw(Box::new(Message::new((*handle).state.generate_msg1())))
        }
        _ => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("invalid state", 1)));
            }
            ptr::null_mut()
        }
    }
}

unsafe fn handle_messages<T, U, H>(
    handle: *mut SignSessionHandle,
    msgs: *const Message,
    msgs_len: usize,
    mut h: H,
    next: Round,
) -> Result<Vec<Message>, GoError>
where
    T: DeserializeOwned,
    U: Serialize + MessageRouting,
    H: FnMut(&mut dsg::State, Vec<T>) -> Result<Vec<U>, dsg::SignError>,
{
    let msgs_slice = std::slice::from_raw_parts(msgs, msgs_len);
    let msgs_vec: Result<Vec<T>, String> = Message::decode_vector(msgs_slice);
    let msgs_vec = match msgs_vec {
        Ok(v) => v,
        Err(e) => return Err(GoError::new(&e, 1)),
    };

    match h(&mut (*handle).state, msgs_vec) {
        Ok(msgs) => {
            let out = Message::encode_vector(msgs);
            (*handle).round = next;
            Ok(out)
        }
        Err(err) => {
            (*handle).round = Round::Failed;
            Err(sign_error_to_go(err))
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_sign_handle_messages(
    handle: *mut SignSessionHandle,
    msgs: *const Message,
    msgs_len: usize,
    seed: *const u8,
    seed_len: usize,
    err_out: *mut *mut GoError,
    out: *mut crate::MessageArray,
) -> c_int {
    if handle.is_null() {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("null handle", 1)));
        }
        return -1;
    }

    let seed = if seed.is_null() || seed_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(seed, seed_len))
    };

    let mut rng = maybe_seeded_rng(seed);

    let result = match &(*handle).round {
        Round::WaitMsg1 => handle_messages(
            handle,
            msgs,
            msgs_len,
            |state, msgs| state.handle_msg1(&mut rng, msgs),
            Round::WaitMsg2,
        ),

        Round::WaitMsg2 => handle_messages(
            handle,
            msgs,
            msgs_len,
            |state, msgs| state.handle_msg2(&mut rng, msgs),
            Round::WaitMsg3,
        ),

        Round::WaitMsg3 => {
            let msgs_slice = std::slice::from_raw_parts(msgs, msgs_len);
            let msgs_vec: Result<Vec<dsg::SignMsg3>, String> =
                Message::decode_vector(msgs_slice);
            let msgs_vec = match msgs_vec {
                Ok(v) => v,
                Err(e) => {
                    (*handle).round = Round::Failed;
                    if !err_out.is_null() {
                        *err_out = Box::into_raw(Box::new(GoError::new(&e, 1)));
                    }
                    return -1;
                }
            };

            match (*handle).state.handle_msg3(msgs_vec) {
                Ok(pre) => {
                    (*handle).round = Round::Pre(pre);
                    Ok(vec![])
                }
                Err(err) => {
                    (*handle).round = Round::Failed;
                    Err(sign_error_to_go(err))
                }
            }
        }

        Round::Failed => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("failed", 1)));
            }
            return -1;
        }

        _ => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("invalid session state", 1)));
            }
            return -1;
        }
    };

    match result {
        Ok(out_vec) => {
            if out_vec.is_empty() {
                if !out.is_null() {
                    (*out).msgs = ptr::null_mut();
                    (*out).len = 0;
                }
                return 0;
            }

            let len = out_vec.len();
            let boxed = out_vec.into_boxed_slice();
            let ptr = Box::into_raw(boxed) as *mut Message;

            if !out.is_null() {
                (*out).msgs = ptr;
                (*out).len = len;
            }
            0
        }
        Err(err) => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(err));
            }
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_sign_last_message(
    handle: *mut SignSessionHandle,
    message_hash: *const u8,
    message_hash_len: usize,
    err_out: *mut *mut GoError,
) -> *mut Message {
    if handle.is_null() {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("null handle", 1)));
        }
        return ptr::null_mut();
    }

    if message_hash_len != 32 {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("invalid message hash", 1)));
        }
        return ptr::null_mut();
    }

    let hash: [u8; 32] = std::slice::from_raw_parts(message_hash, 32)
        .try_into()
        .unwrap();

    let round = std::mem::replace(&mut (*handle).round, Round::Finished);
    match round {
        Round::Pre(pre) => {
            let (partial, msg4) = dsg::create_partial_signature(pre, hash);
            (*handle).round = Round::WaitMsg4(partial);
            Box::into_raw(Box::new(Message::new(msg4)))
        }
        prev => {
            (*handle).round = prev;
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("invalid state", 1)));
            }
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_sign_combine(
    handle: *mut SignSessionHandle,
    msgs: *const Message,
    msgs_len: usize,
    r_out: *mut u8,
    s_out: *mut u8,
    err_out: *mut *mut GoError,
) -> c_int {
    if handle.is_null() || r_out.is_null() || s_out.is_null() {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("null handle or output", 1)));
        }
        return -1;
    }

    let round = std::mem::replace(&mut (*handle).round, Round::Finished);
    match round {
        Round::WaitMsg4(partial) => {
            let msgs_slice = std::slice::from_raw_parts(msgs, msgs_len);
            let msgs_vec: Result<Vec<dsg::SignMsg4>, String> =
                Message::decode_vector(msgs_slice);
            let msgs_vec = match msgs_vec {
                Ok(v) => v,
                Err(e) => {
                    let _ = Box::from_raw(handle);
                    if !err_out.is_null() {
                        *err_out = Box::into_raw(Box::new(GoError::new(&e, 1)));
                    }
                    return -1;
                }
            };

            match dsg::combine_signatures(partial, msgs_vec) {
                Ok(sign) => {
                    let (r, s) = sign.split_bytes();
                    if r.len() != 32 || s.len() != 32 {
                        if !err_out.is_null() {
                            *err_out = Box::into_raw(Box::new(GoError::new("invalid signature size", 1)));
                        }
                        let _ = Box::from_raw(handle);
                        return -1;
                    }

                    ptr::copy_nonoverlapping(r.as_ptr(), r_out, 32);
                    ptr::copy_nonoverlapping(s.as_ptr(), s_out, 32);

                    let _ = Box::from_raw(handle);
                    0
                }
                Err(err) => {
                    let _ = Box::from_raw(handle);
                    if !err_out.is_null() {
                        *err_out = Box::into_raw(Box::new(sign_error_to_go(err)));
                    }
                    -1
                }
            }
        }
        _ => {
            let _ = Box::from_raw(handle);
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("invalid state", 1)));
            }
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_sign_free(handle: *mut SignSessionHandle) {
    if handle.is_null() {
        return;
    }
    let _ = Box::from_raw(handle);
}

impl MessageRouting for dsg::SignMsg1 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for dsg::SignMsg2 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        Some(self.to_id)
    }
}

impl MessageRouting for dsg::SignMsg3 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        Some(self.to_id)
    }
}

impl MessageRouting for dsg::SignMsg4 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

use std::str::FromStr;

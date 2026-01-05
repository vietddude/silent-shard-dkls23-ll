// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::os::raw::{c_int, c_uchar};
use std::ptr;

use k256::elliptic_curve::group::GroupEncoding;
use k256::AffinePoint;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use dkls23_ll::dkg::{self, KeygenError};

use crate::{
    errors::keygen_error_to_go,
    keyshare::KeyshareHandle,
    maybe_seeded_rng,
    message::{Message, MessageRouting},
    ByteBuffer, GoError,
};

#[derive(Serialize, Deserialize, Clone)]
#[allow(clippy::large_enum_variant)]
enum Round {
    Init,
    WaitMsg1,
    WaitMsg2,
    WaitMsg3,
    WaitMsg4,
    Failed,
    Share(dkg::Keyshare),
}

#[repr(C)]
pub struct KeygenSessionHandle {
    state: dkg::State,
    n: usize,
    round: Round,
}

impl KeygenSessionHandle {
    fn new(state: dkg::State, n: usize) -> Self {
        Self {
            state,
            n,
            round: Round::Init,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keygen_new(
    participants: c_uchar,
    threshold: c_uchar,
    party_id: c_uchar,
    seed: *const u8,
    seed_len: usize,
) -> *mut KeygenSessionHandle {
    let seed = if seed.is_null() || seed_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(seed, seed_len))
    };

    let mut rng = maybe_seeded_rng(seed);

    let party = dkg::Party {
        ranks: vec![0; participants as usize],
        t: threshold,
        party_id,
    };

    let n = party.ranks.len();
    let state = dkg::State::new(party, &mut rng);

    Box::into_raw(Box::new(KeygenSessionHandle::new(state, n)))
}

#[derive(Serialize, Deserialize)]
struct KeygenSessionSerializable {
    n: usize,
    round: Round,
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keygen_to_bytes(
    handle: *const KeygenSessionHandle,
) -> ByteBuffer {
    if handle.is_null() {
        return ByteBuffer {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
    }

    // Note: State cannot be serialized, so we only serialize the round and n
    // The state will need to be reconstructed from the round if needed
    // For now, we serialize what we can
    let serializable = KeygenSessionSerializable {
        n: (*handle).n,
        round: match &(*handle).round {
            Round::Init => Round::Init,
            Round::WaitMsg1 => Round::WaitMsg1,
            Round::WaitMsg2 => Round::WaitMsg2,
            Round::WaitMsg3 => Round::WaitMsg3,
            Round::WaitMsg4 => Round::WaitMsg4,
            Round::Failed => Round::Failed,
            Round::Share(share) => Round::Share(share.clone()),
        },
    };

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
pub unsafe extern "C" fn dkls_keygen_from_bytes(
    _bytes: *const u8,
    _len: usize,
) -> *mut KeygenSessionHandle {
    // Note: We cannot fully deserialize because State is not serializable
    // This function is provided for API compatibility but will return null
    // In practice, sessions should be kept in memory and not serialized mid-protocol
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keygen_init_key_rotation(
    oldshare: *const KeyshareHandle,
    seed: *const u8,
    seed_len: usize,
    err_out: *mut *mut GoError,
) -> *mut KeygenSessionHandle {
    if oldshare.is_null() {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("null keyshare", 1)));
        }
        return ptr::null_mut();
    }

    let seed = if seed.is_null() || seed_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(seed, seed_len))
    };

    let mut rng = maybe_seeded_rng(seed);
    let oldshare = &(*oldshare).inner;

    match dkg::State::key_rotation(oldshare, &mut rng) {
        Ok(state) => {
            let n = oldshare.rank_list.len();
            Box::into_raw(Box::new(KeygenSessionHandle::new(state, n)))
        }
        Err(e) => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(keygen_error_to_go(e)));
            }
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keygen_init_key_recovery(
    oldshare: *const KeyshareHandle,
    lost_shares: *const u8,
    lost_shares_len: usize,
    seed: *const u8,
    seed_len: usize,
    err_out: *mut *mut GoError,
) -> *mut KeygenSessionHandle {
    if oldshare.is_null() {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("null keyshare", 1)));
        }
        return ptr::null_mut();
    }

    let seed = if seed.is_null() || seed_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(seed, seed_len))
    };

    let mut rng = maybe_seeded_rng(seed);
    let oldshare = &(*oldshare).inner;
    let lost_shares_vec = std::slice::from_raw_parts(lost_shares, lost_shares_len).to_vec();

    match dkg::State::key_refresh(
        &dkg::RefreshShare::from_keyshare(oldshare, Some(&lost_shares_vec)),
        &mut rng,
    ) {
        Ok(state) => {
            let n = oldshare.rank_list.len();
            Box::into_raw(Box::new(KeygenSessionHandle::new(state, n)))
        }
        Err(e) => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(keygen_error_to_go(e)));
            }
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keygen_init_lost_share_recovery(
    participants: c_uchar,
    threshold: c_uchar,
    party_id: c_uchar,
    pk: *const u8,
    pk_len: usize,
    lost_shares: *const u8,
    lost_shares_len: usize,
    seed: *const u8,
    seed_len: usize,
    err_out: *mut *mut GoError,
) -> *mut KeygenSessionHandle {
    if pk_len != 33 {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("invalid PK size", 1)));
        }
        return ptr::null_mut();
    }

    let seed = if seed.is_null() || seed_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(seed, seed_len))
    };

    let mut rng = maybe_seeded_rng(seed);

    let party = dkg::Party {
        ranks: vec![0; participants as usize],
        t: threshold,
        party_id,
    };

    let pk_bytes: [u8; 33] = std::slice::from_raw_parts(pk, 33).try_into().unwrap();
    let pk: Option<AffinePoint> = AffinePoint::from_bytes(&pk_bytes.into()).into();
    let pk = match pk {
        Some(pk) => pk,
        None => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("invalid PK", 1)));
            }
            return ptr::null_mut();
        }
    };

    let lost_shares_vec = std::slice::from_raw_parts(lost_shares, lost_shares_len).to_vec();

    match dkg::State::key_refresh(
        &dkg::RefreshShare::from_lost_keyshare(party, pk, lost_shares_vec),
        &mut rng,
    ) {
        Ok(state) => {
            let n = participants as usize;
            Box::into_raw(Box::new(KeygenSessionHandle::new(state, n)))
        }
        Err(e) => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(keygen_error_to_go(e)));
            }
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keygen_create_first_message(
    handle: *mut KeygenSessionHandle,
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

#[no_mangle]
pub unsafe extern "C" fn dkls_keygen_calculate_commitment_2(
    handle: *const KeygenSessionHandle,
    out: *mut u8,
) -> c_int {
    if handle.is_null() || out.is_null() {
        return -1;
    }

    let commitment = (*handle).state.calculate_commitment_2();
    if commitment.len() != 32 {
        return -1;
    }

    ptr::copy_nonoverlapping(commitment.as_ptr(), out, 32);
    0
}

unsafe fn handle_messages<T, U, H>(
    handle: *mut KeygenSessionHandle,
    msgs: *const Message,
    msgs_len: usize,
    mut h: H,
    next: Round,
) -> Result<Vec<Message>, GoError>
where
    T: DeserializeOwned,
    U: Serialize + MessageRouting,
    H: FnMut(&mut dkg::State, Vec<T>) -> Result<Vec<U>, KeygenError>,
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
            Err(keygen_error_to_go(err))
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keygen_handle_messages(
    handle: *mut KeygenSessionHandle,
    msgs: *const Message,
    msgs_len: usize,
    commitments: *const u8,
    commitments_len: usize,
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
            if commitments.is_null() || commitments_len == 0 {
                if !err_out.is_null() {
                    *err_out = Box::into_raw(Box::new(GoError::new(
                        "commitments required",
                        1,
                    )));
                }
                return -1;
            }

            let n = (*handle).n;
            if commitments_len != n * 32 {
                if !err_out.is_null() {
                    *err_out = Box::into_raw(Box::new(GoError::new(
                        "invalid commitments length",
                        1,
                    )));
                }
                return -1;
            }

            let commitments: Vec<[u8; 32]> = std::slice::from_raw_parts(commitments, commitments_len)
                .chunks_exact(32)
                .map(|chunk| chunk.try_into().unwrap())
                .collect();

            handle_messages(
                handle,
                msgs,
                msgs_len,
                |state, msgs| {
                    state
                        .handle_msg3(&mut rng, msgs, &commitments)
                        .map(|m| vec![m])
                },
                Round::WaitMsg4,
            )
        }

        Round::WaitMsg4 => {
            let msgs_slice = std::slice::from_raw_parts(msgs, msgs_len);
            let msgs_vec: Result<Vec<dkg::KeygenMsg4>, String> =
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

            match (*handle).state.handle_msg4(msgs_vec) {
                Ok(keyshare) => {
                    (*handle).round = Round::Share(keyshare);
                    Ok(vec![])
                }
                Err(err) => {
                    (*handle).round = Round::Failed;
                    Err(keygen_error_to_go(err))
                }
            }
        }

        Round::Failed => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("failed session", 1)));
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
pub unsafe extern "C" fn dkls_keygen_keyshare(
    handle: *mut KeygenSessionHandle,
    err_out: *mut *mut GoError,
) -> *mut KeyshareHandle {
    if handle.is_null() {
        if !err_out.is_null() {
            *err_out = Box::into_raw(Box::new(GoError::new("null handle", 1)));
        }
        return ptr::null_mut();
    }

    let round = std::mem::replace(&mut (*handle).round, Round::Failed);
    match round {
        Round::Share(share) => {
            let _ = Box::from_raw(handle);
            Box::into_raw(Box::new(KeyshareHandle::new(share)))
        }
        Round::Failed => {
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("failed", 1)));
            }
            ptr::null_mut()
        }
        _ => {
            let _ = Box::from_raw(handle);
            if !err_out.is_null() {
                *err_out = Box::into_raw(Box::new(GoError::new("keygen-in-progress", 1)));
            }
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dkls_keygen_free(handle: *mut KeygenSessionHandle) {
    if handle.is_null() {
        return;
    }
    let _ = Box::from_raw(handle);
}

impl MessageRouting for dkg::KeygenMsg1 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for dkg::KeygenMsg2 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        Some(self.to_id)
    }
}

impl MessageRouting for dkg::KeygenMsg3 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        Some(self.to_id)
    }
}

impl MessageRouting for dkg::KeygenMsg4 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

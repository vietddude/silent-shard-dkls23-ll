// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::GoError;
use dkls23_ll::{dkg::KeygenError, dsg::SignError, dsg_ot_variant::SignOTVariantError};

pub fn keygen_error_to_go(err: KeygenError) -> GoError {
    GoError::new(&err.to_string(), 1)
}

pub fn sign_error_to_go(err: SignError) -> GoError {
    let code = if matches!(err, SignError::AbortProtocolAndBanParty(_)) {
        2
    } else {
        1
    };
    GoError::new(&err.to_string(), code)
}

#[allow(dead_code)]
pub fn sign_ot_variant_error_to_go(err: SignOTVariantError) -> GoError {
    GoError::new(&err.to_string(), 1)
}

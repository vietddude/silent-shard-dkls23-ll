// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::ffi::CStr;
use std::os::raw::c_char;

pub unsafe fn c_str_to_string(c_str: *const c_char) -> Result<String, String> {
    if c_str.is_null() {
        return Err("null pointer".to_string());
    }
    let c_str = CStr::from_ptr(c_str);
    c_str.to_str()
        .map(|s| s.to_string())
        .map_err(|e| format!("invalid UTF-8: {}", e))
}


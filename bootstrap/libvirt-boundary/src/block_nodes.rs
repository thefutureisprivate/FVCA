use std::ffi::{CStr, c_char, c_int, c_void};
use std::io;
use std::ptr::null_mut;

const ARRAY: c_int = 5;
const BOOLEAN: c_int = 1;
const STRING: c_int = 6;
const STATE_DISK: &CStr = c"/run/fvca/guest-state.raw";

#[link(name = "json-c")]
unsafe extern "C" {
    fn json_tokener_parse(input: *const c_char) -> *mut c_void;
    fn json_object_put(object: *mut c_void) -> c_int;
    fn json_object_is_type(object: *const c_void, kind: c_int) -> c_int;
    fn json_object_object_get_ex(object: *const c_void, key: *const c_char, result: *mut *const c_void) -> c_int;
    fn json_object_array_length(object: *const c_void) -> usize;
    fn json_object_array_get_idx(object: *const c_void, index: usize) -> *const c_void;
    fn json_object_get_boolean(object: *const c_void) -> c_int;
    fn json_object_get_string(object: *mut c_void) -> *const c_char;
}

struct Reply(*mut c_void);

impl Drop for Reply {
    fn drop(&mut self) {
        // Release the tree ownership returned by json_tokener_parse.
        unsafe { json_object_put(self.0) };
    }
}

fn field(object: *const c_void, key: &CStr) -> *const c_void {
    let mut result = null_mut::<c_void>().cast_const();
    // The tree stays live throughout verification. Absent fields leave a null result.
    unsafe { json_object_object_get_ex(object, key.as_ptr(), &mut result) };
    result
}

fn boolean(object: *const c_void, key: &CStr) -> Option<bool> {
    let value = field(object, key);
    // Check the type before reading to prevent json-c value coercion.
    unsafe { (json_object_is_type(value, BOOLEAN) != 0).then(|| json_object_get_boolean(value) != 0) }
}

fn string_is(object: *const c_void, key: &CStr, expected: &CStr) -> bool {
    let value = field(object, key);
    // A JSON string provides a NUL-terminated buffer owned by the live tree.
    unsafe {
        json_object_is_type(value, STRING) != 0
            && CStr::from_ptr(json_object_get_string(value.cast_mut())) == expected
    }
}

pub fn verify(reply: &CStr, active: bool) -> io::Result<()> {
    if reply.to_bytes().len() > 64 * 1024 {
        return Err(io::Error::other("the QEMU block inventory exceeds its size limit"));
    }
    let reply = Reply(unsafe { json_tokener_parse(reply.as_ptr()) });
    let nodes = field(reply.0, c"return");
    // The QMP response must be an array of named block nodes.
    if unsafe { json_object_is_type(nodes, ARRAY) } == 0 {
        return Err(io::Error::other("invalid QEMU block inventory"));
    }
    let mut raw = 0;
    let mut file = 0;
    // The checked array type guards both accessors and index stays in bounds.
    for index in 0..unsafe { json_object_array_length(nodes) } {
        let node = unsafe { json_object_array_get_idx(nodes, index) };
        if boolean(node, c"ro") == Some(true) && !string_is(node, c"file", STATE_DISK) {
            continue;
        }
        if !string_is(node, c"file", STATE_DISK)
            || boolean(node, c"ro") != Some(false)
            || boolean(node, c"active") != Some(active)
            || boolean(field(node, c"cache"), c"no-flush") != Some(false)
        {
            return Err(io::Error::other("unexpected writable Guest block node or activity state"));
        }
        if string_is(node, c"drv", c"raw") {
            raw += 1;
        } else if string_is(node, c"drv", c"file") && boolean(field(node, c"cache"), c"direct") == Some(true) {
            file += 1;
        } else {
            return Err(io::Error::other("unexpected writable Guest block driver or cache mode"));
        }
    }
    if raw > 1 || file != 1 {
        return Err(io::Error::other("unexpected number of block nodes for the writable Guest disk"));
    }
    Ok(())
}

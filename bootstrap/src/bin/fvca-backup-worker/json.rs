use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io;
use std::ptr::{NonNull, null};

use fvca_initrd_bootstrap::invalid;

const INTEGER: c_int = 3;
const OBJECT: c_int = 4;
const STRING: c_int = 6;

#[link(name = "json-c")]
unsafe extern "C" {
    fn json_tokener_parse(input: *const c_char) -> *mut c_void;
    fn json_object_put(object: *mut c_void) -> c_int;
    fn json_object_is_type(object: *const c_void, kind: c_int) -> c_int;
    fn json_object_object_get_ex(object: *const c_void, key: *const c_char, result: *mut *const c_void) -> c_int;
    fn json_object_get_int64(object: *const c_void) -> i64;
    fn json_object_get_string(object: *const c_void) -> *const c_char;
    fn json_object_get_string_len(object: *const c_void) -> c_int;
}

pub struct Object(NonNull<c_void>);

impl Object {
    pub fn parse(line: &[u8]) -> io::Result<Self> {
        let input = CString::new(line).map_err(io::Error::other)?;
        // The parser returns an independent tree which this object owns.
        let result = unsafe { json_tokener_parse(input.as_ptr()) };
        let value = Self(NonNull::new(result).ok_or_else(|| invalid("invalid restic JSON"))?);
        if unsafe { json_object_is_type(value.0.as_ptr(), OBJECT) } == 0 {
            return Err(invalid("expected a restic JSON object"));
        }
        Ok(value)
    }

    fn field(&self, key: &CStr) -> *const c_void {
        let mut output = null();
        // Nodes are borrowed from the tree, which stays live through the access.
        unsafe { json_object_object_get_ex(self.0.as_ptr(), key.as_ptr(), &mut output) };
        output
    }

    pub fn text(&self, key: &CStr) -> io::Result<&str> {
        let field = self.field(key);
        if unsafe { json_object_is_type(field, STRING) } == 0 {
            return Err(invalid("missing restic string field"));
        }
        // json-c owns the string and reports its length including embedded NULs.
        let bytes = unsafe { CStr::from_ptr(json_object_get_string(field)) }.to_bytes();
        if usize::try_from(unsafe { json_object_get_string_len(field) }).ok() != Some(bytes.len()) {
            return Err(invalid("invalid restic string field"));
        }
        std::str::from_utf8(bytes).map_err(io::Error::other)
    }

    pub fn integer(&self, key: &CStr) -> io::Result<u64> {
        let field = self.field(key);
        if unsafe { json_object_is_type(field, INTEGER) } == 0 {
            return Err(invalid("missing restic integer field"));
        }
        u64::try_from(unsafe { json_object_get_int64(field) }).map_err(io::Error::other)
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        // Release the parser's owned tree.
        unsafe { json_object_put(self.0.as_ptr()) };
    }
}

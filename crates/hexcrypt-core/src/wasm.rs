//! wasm-bindgen surface. Thin: validate, call core, map errors to JS.
use wasm_bindgen::prelude::*;

use crate::{Envelope, Kind, KEY_LEN};

fn key(k: &[u8]) -> Result<[u8; KEY_LEN], JsError> {
    k.try_into().map_err(|_| JsError::new(&crate::Error::BadKey.to_string()))
}
fn js<T>(r: Result<T, crate::Error>) -> Result<T, JsError> {
    r.map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn new_id() -> Result<String, JsError> {
    js(crate::new_id())
}

#[wasm_bindgen]
pub fn new_key() -> Result<Vec<u8>, JsError> {
    js(crate::new_key().map(|k| k.to_vec()))
}

#[wasm_bindgen]
pub fn encode_key(k: &[u8]) -> Result<String, JsError> {
    Ok(crate::encode_key(&key(k)?))
}

#[wasm_bindgen]
pub fn decode_key(s: &str) -> Result<Vec<u8>, JsError> {
    js(crate::decode_key(s).map(|k| k.to_vec()))
}

/// kind: 0 = text, 1 = file. `name` is ignored for text.
#[wasm_bindgen]
pub fn encrypt(id: &str, k: &[u8], kind: u8, name: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
    let env = if kind == 0 {
        Envelope { kind: Kind::Text, name: String::new(), data: data.to_vec() }
    } else {
        Envelope::file(name, data.to_vec())
    };
    js(crate::encrypt(id, &key(k)?, &env.to_bytes()))
}

#[wasm_bindgen]
pub struct Opened {
    kind: u8,
    name: String,
    data: Vec<u8>,
}

#[wasm_bindgen]
impl Opened {
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> u8 {
        self.kind
    }
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }
}

#[wasm_bindgen]
pub fn decrypt(id: &str, k: &[u8], blob: &[u8]) -> Result<Opened, JsError> {
    let pt = js(crate::decrypt(id, &key(k)?, blob))?;
    let env = js(Envelope::from_bytes(&pt))?;
    Ok(Opened { kind: env.kind as u8, name: env.name, data: env.data })
}

use std::iter::repeat;

use crypto::{
  aead::{AeadDecryptor, AeadEncryptor},
  aes::KeySize::KeySize256,
  aes_gcm::AesGcm,
};

use crate::common::types::AEAD;

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
  let nonce: Vec<u8> = repeat(3).take(12).collect();
  let aad: [u8; 0] = [];
  let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
  let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
  let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
  gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
  AEAD {
    ciphertext: out.to_vec(),
    tag: out_tag.to_vec(),
  }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
  let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
  let nonce: Vec<u8> = repeat(3).take(12).collect();
  let aad: [u8; 0] = [];
  let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
  gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
  out
}

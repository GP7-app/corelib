use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
  Keys, Parameters, SharedKeys,
};
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct AEAD {
  pub ciphertext: Vec<u8>,
  pub tag: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreParameters {
  pub threshold: u16,   //t
  pub share_count: u16, //n
}

impl From<Parameters> for KeystoreParameters {
  fn from(param: Parameters) -> Self {
    return KeystoreParameters {
      threshold: param.threshold,
      share_count: param.share_count,
    };
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
  pub params: KeystoreParameters,
  pub party_key: Keys,
  pub party_shares: Vec<FE>,
  pub shared_keys: SharedKeys,
  pub party_index: usize,
  pub vss_scheme_vec: Vec<VerifiableSS>,
  pub paillier_key_vec: Vec<EncryptionKey>,
  pub y_sum: GE,
}

use crate::common::types::{Keystore, AEAD};
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::mta::{MessageA, MessageB};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Phase5ADecom1, Phase5Com1, Phase5Com2,
    Phase5DDecom2, SignBroadcastPhase1, SignDecommitPhase1, Signature,
};

use curv::cryptographic_primitives::{
    proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof, proofs::sigma_dlog::DLogProof,
    secret_sharing::feldman_vss::VerifiableSS,
};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum Errors {
    Halted = 0,
    Unknown = 1,

    CollectTimeout = 10,
    CollectUnexpectedData = 11,
    CollectDisconnected = 12,
}

impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Common error: {:?}", self)
    }
}

impl std::error::Error for Errors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OutgoingMessages {
    Send {
        sender: u8,
        target: u8,
        data: MessageData,
    },
    Complete(RoundResult),
    Quit,
    Error(Errors),
    Log(String),
}

impl Display for IncomingMessages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncomingMessages::Send {
                sender,
                target,
                data,
            } => write!(f, "Receive from {} to {}: {}", sender, target, data),
        }
    }
}
impl Display for OutgoingMessages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutgoingMessages::Send {
                sender,
                target,
                data,
            } => write!(f, "Send from {} to {}: {}", sender, target, data),
            OutgoingMessages::Complete(r) => write!(f, "Complete with {}", r),
            OutgoingMessages::Quit => write!(f, "Quit"),
            OutgoingMessages::Error(e) => write!(f, "Error (code {})", *e as i32),
            OutgoingMessages::Log(e) => write!(f, "Log {}", e),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IncomingMessages {
    Send {
        sender: u8,
        target: u8,
        data: MessageData,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RoundResult {
    KeyGen {
        private_key: Keystore,
        public_key: GE,
    },
    Sign {
        signature: Signature,
    },
}

impl Display for RoundResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundResult::KeyGen { public_key, .. } => write!(f, "KeyGen {:?}", public_key),
            RoundResult::Sign { signature } => write!(f, "Signature: {:?}", signature),
        }
    }
}

impl RoundResult {
    pub fn as_signature(&self) -> Option<&Signature> {
        match self {
            RoundResult::Sign { signature } => Some(signature),
            _ => None,
        }
    }

    pub fn as_keystore(&self) -> Option<&Keystore> {
        match self {
            RoundResult::KeyGen { private_key, .. } => Some(private_key),
            _ => None,
        }
    }

    pub fn as_public_key(&self) -> Option<&GE> {
        match self {
            RoundResult::KeyGen { public_key, .. } => Some(public_key),
            _ => None,
        }
    }

    pub fn as_keygen(&self) -> Option<(&Keystore, &GE)> {
        match self {
            RoundResult::KeyGen {
                public_key,
                private_key,
            } => Some((private_key, public_key)),
            _ => None,
        }
    }
}
// pub struct SignRound1Message(pub SignBroadcastPhase1, pub MessageA);

// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct SignRound2Message(pub MessageB, pub MessageB);

// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct SignRound6Message(pub Phase5ADecom1, pub HomoELGamalProof);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignRound1Data {
    pub com: SignBroadcastPhase1,
    pub enc: MessageA,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignRound2Data {
    pub g: MessageB,
    pub w: MessageB,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignRound6Data {
    pub com: Phase5ADecom1,
    pub proof: HomoELGamalProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum MessageData {
    None,
    KeyGenRound1(KeyGenBroadcastMessage1),
    KeyGenRound2(KeyGenDecommitMessage1),
    KeyGenRound3(AEAD),
    KeyGenRound4(VerifiableSS),
    KeyGenRound5(DLogProof),

    SignRound1(SignRound1Data),
    SignRound2(SignRound2Data),
    SignRound3(FE),
    SignRound4(SignDecommitPhase1),
    SignRound5(Phase5Com1),
    SignRound6(SignRound6Data),
    SignRound7(Phase5Com2),
    SignRound8(Phase5DDecom2),
    SignRound9(FE),
}

impl std::fmt::Display for MessageData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageData::KeyGenRound1(_) => write!(f, "Message: {}", "KeyGenRound1"),
            MessageData::KeyGenRound2(_) => write!(f, "Message: {}", "KeyGenRound2"),
            MessageData::KeyGenRound3(_) => write!(f, "Message: {}", "KeyGenRound3"),
            MessageData::KeyGenRound4(_) => write!(f, "Message: {}", "KeyGenRound4"),
            MessageData::KeyGenRound5(_) => write!(f, "Message: {}", "KeyGenRound5"),

            MessageData::SignRound1(_) => write!(f, "Message: {}", "SignRound1"),
            MessageData::SignRound2(_) => write!(f, "Message: {}", "SignRound2"),
            MessageData::SignRound3(_) => write!(f, "Message: {}", "SignRound3"),
            MessageData::SignRound4(_) => write!(f, "Message: {}", "SignRound4"),
            MessageData::SignRound5(_) => write!(f, "Message: {}", "SignRound5"),
            MessageData::SignRound6(_) => write!(f, "Message: {}", "SignRound6"),
            MessageData::SignRound7(_) => write!(f, "Message: {}", "SignRound7"),
            MessageData::SignRound8(_) => write!(f, "Message: {}", "SignRound8"),
            MessageData::SignRound9(_) => write!(f, "Message: {}", "SignRound9"),
            _ => write!(f, "Message: Error"),
        }
    }
}

pub trait FromData
where
    Self: Sized,
{
    fn get_from_data(data: MessageData) -> Option<Self>;
}

impl FromData for KeyGenBroadcastMessage1 {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::KeyGenRound1(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for KeyGenDecommitMessage1 {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::KeyGenRound2(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for AEAD {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::KeyGenRound3(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for VerifiableSS {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::KeyGenRound4(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for DLogProof {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::KeyGenRound5(value) => Some(value),
            _ => None,
        }
    }
}

impl FromData for SignRound1Data {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::SignRound1(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for SignRound2Data {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::SignRound2(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for FE {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::SignRound3(value) => Some(value),
            MessageData::SignRound9(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for SignDecommitPhase1 {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::SignRound4(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for Phase5Com1 {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::SignRound5(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for SignRound6Data {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::SignRound6(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for Phase5Com2 {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::SignRound7(value) => Some(value),
            _ => None,
        }
    }
}
impl FromData for Phase5DDecom2 {
    fn get_from_data(data: MessageData) -> Option<Self> {
        match data {
            MessageData::SignRound8(value) => Some(value),
            _ => None,
        }
    }
}

pub trait GetData<T> {
    fn get_data(self) -> Option<T>;
}

impl GetData<KeyGenBroadcastMessage1> for MessageData {
    fn get_data(self) -> Option<KeyGenBroadcastMessage1> {
        match self {
            MessageData::KeyGenRound1(value) => Some(value.clone()),
            _ => None,
        }
    }
}
impl GetData<KeyGenDecommitMessage1> for MessageData {
    fn get_data(self) -> Option<KeyGenDecommitMessage1> {
        match self {
            MessageData::KeyGenRound2(value) => Some(value.clone()),
            _ => None,
        }
    }
}
impl GetData<AEAD> for MessageData {
    fn get_data(self) -> Option<AEAD> {
        match self {
            MessageData::KeyGenRound3(value) => Some(value.clone()),
            _ => None,
        }
    }
}
impl GetData<VerifiableSS> for MessageData {
    fn get_data(self) -> Option<VerifiableSS> {
        match self {
            MessageData::KeyGenRound4(value) => Some(value.clone()),
            _ => None,
        }
    }
}
impl GetData<DLogProof> for MessageData {
    fn get_data(self) -> Option<DLogProof> {
        match self {
            MessageData::KeyGenRound5(value) => Some(value.clone()),
            _ => None,
        }
    }
}

impl OutgoingMessages {
    pub fn into_incoming(&self) -> Option<IncomingMessages> {
        match self {
            OutgoingMessages::Send {
                sender,
                target,
                data,
            } => Some(IncomingMessages::Send {
                sender: sender.clone(),
                target: target.clone(),
                data: data.clone(),
            }),
            _ => None,
        }
    }
    #[allow(dead_code)]
    pub fn make_send(sender: u8, target: u8, data: &MessageData) -> Self {
        OutgoingMessages::Send {
            sender,
            target,
            data: data.clone(), //base64::encode(bincode::serialize(data).unwrap().as_slice()),
        }
    }

    pub fn make_complete_keygen(keystore: &Keystore) -> Self {
        OutgoingMessages::Complete(RoundResult::KeyGen {
            private_key: keystore.clone(), // base64::encode(bincode::serialize(&keystore).unwrap().as_slice()),
            public_key: keystore.y_sum.clone(),
        })
    }

    pub fn make_complete_signature(sig: Signature) -> Self {
        OutgoingMessages::Complete(RoundResult::Sign {
            signature: sig, //base64::encode(bincode::serialize(&sig).unwrap().as_slice()),
        })
    }
}

// impl From<Vec<u8>> for MessageData {
//     fn from(input: Vec<u8>) -> Self {
//         bincode::deserialize::<MessageData>(&input.as_slice()).unwrap()
//     }
// }

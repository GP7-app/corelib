use crate::common::messages::*;
use crate::common::types::{Keystore, KeystoreParameters, AEAD};
use crate::common::utils::{aes_decrypt, aes_encrypt};
use crate::errors::CoreErrors;
use curv::{
  arithmetic::traits::Converter,
  cryptographic_primitives::{
    proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof, proofs::sigma_dlog::DLogProof,
    secret_sharing::feldman_vss::VerifiableSS,
  },
  elliptic::curves::traits::{ECPoint, ECScalar},
  BigInt, FE, GE,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::{
  mta::{MessageA, MessageB},
  party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters,
    PartyPrivate, Phase5ADecom1, SharedKeys, SignBroadcastPhase1, SignKeys,
  },
};
use paillier::EncryptionKey;
use std::fmt::Debug;
use std::sync::mpsc::*;
use std::thread;

fn broadcast(
  sender: &Sender<OutgoingMessages>,
  participants: u8,
  party_id: u8,
  data: &MessageData,
) -> Result<(), CoreErrors> {
  for p in (0..participants).filter(|p| *p != party_id) {
    sendp2p(sender, p, party_id, data)?;
  }

  Ok(())
}

fn sendp2p(
  sender: &Sender<OutgoingMessages>,
  target: u8,
  party_id: u8,
  data: &MessageData,
) -> Result<(), CoreErrors> {
  let msg = OutgoingMessages::make_send(party_id, target, data);
  let error_msg = format!("Failed to send {}", msg);
  sender
    .send(msg)
    .map_err(|_| CoreErrors::TransportIssue(error_msg))
}

#[allow(unreachable_patterns, dead_code)]
fn parse_incoming(msg: IncomingMessages) -> Result<(u8, u8, MessageData), CoreErrors> {
  match msg {
    IncomingMessages::Send {
      sender,
      target,
      data,
    } => Ok((sender, target, data)),
    _ => Err(CoreErrors::InvalidData(format!(
      "Unexpected incoming message ({})",
      msg
    ))),
  }
}

fn log(sender: &Sender<OutgoingMessages>, msg: String) -> Result<(), CoreErrors> {
  let msg = OutgoingMessages::Log(msg);
  let error_msg = format!("Failed to send {}", msg);
  sender
    .send(msg)
    .map_err(|_| CoreErrors::TransportIssue(error_msg))
}

fn err(sender: &Sender<OutgoingMessages>, error: Errors) -> Result<(), CoreErrors> {
  let msg = OutgoingMessages::Error(error);
  let error_msg = format!("Failed to send {}", msg);
  sender
    .send(msg)
    .map_err(|_| CoreErrors::TransportIssue(error_msg))
}

// #[derive(Debug, Serialize, Deserialize, Clone, Copy)]
// enum CollectError {
//   Timeout,
//   UnexpectedData,
//   Disconnected,
// }

// impl From<CollectError> for Errors {
//   fn from(e: CollectError) -> Self {
//     match e {
//       CollectError::Timeout => Errors::CollectTimeout,
//       CollectError::UnexpectedData => Errors::CollectUnexpectedData,
//       CollectError::Disconnected => Errors::CollectDisconnected,
//     }
//   }
// }

fn collect_round<T>(
  incoming_receiver: &Receiver<IncomingMessages>,
  outgoing_sender: &Sender<OutgoingMessages>,
  my_value: T,
  party_id: u8,
  participants: u8,
) -> Result<Vec<T>, CoreErrors>
where
  T: FromData + Sized + Clone + Debug,
{
  let participants = participants as usize;
  let mut vec: Vec<Option<T>> = Vec::new();

  vec.resize(participants, None);
  vec[party_id as usize] = Some(my_value);

  // collection not more than 5 sec
  let mut timeout = 3000;

  loop {
    timeout -= 100;
    thread::sleep(std::time::Duration::from_millis(100));
    if timeout <= 0 {
      log(
        &outgoing_sender,
        format!("Collecting data timeout achived. Halt the process"),
      )?;
      return Err(CoreErrors::Timeout(format!("Collecting time is over")));
    }

    if vec.iter().all(|r| r.is_some()) {
      break;
    }

    let result = match incoming_receiver.try_recv() {
      Ok(result) => Some(Ok(result)),
      Err(TryRecvError::Disconnected) => Some(Err(CoreErrors::TransportIssue(format!(
        "Incoming message channel is closed"
      )))),
      Err(TryRecvError::Empty) => None,
    };

    if let Some(result) = result {
      let (sender, _, data) = parse_incoming(result?)?;
      log(
        &outgoing_sender,
        format!(
          "Received {} from {} (duplicate? {})",
          &data,
          sender,
          vec[sender as usize].is_some()
        ),
      )?;
      let err_msg = format!("Unexpected incoming data ({})", data);
      let tvalue = T::get_from_data(data).ok_or(CoreErrors::InvalidData(err_msg))?;
      vec[sender as usize] = Some(tvalue);
    } else {
      continue;
    }
  }

  if vec.iter().any(|r| r.is_none()) {
    return Err(CoreErrors::InvalidData(format!("Unexpected empty result")));
  }

  Ok(
    vec
      .iter()
      .map(|x| x.as_ref().unwrap().clone())
      .collect::<Vec<T>>(),
  )
}

pub fn sign(
  participants: u8,
  threshold: u8,
  party_num_id: u8,
  keystore: &Keystore,
  digest: &BigInt,
  signers_vec: &Vec<usize>,
  outgoing_sender: Sender<OutgoingMessages>,
  incoming_receiver: Receiver<IncomingMessages>,
) {
  if let Err(e) = safe_sign(
    participants,
    threshold,
    party_num_id,
    keystore,
    digest,
    signers_vec,
    outgoing_sender.clone(),
    incoming_receiver,
  ) {
    outgoing_sender.send(OutgoingMessages::Log(format!("Error: {}", e)));
    outgoing_sender.send(OutgoingMessages::Error(Errors::Halted));
  }
}
pub fn safe_sign(
  participants: u8,
  threshold: u8,
  party_num_id: u8,
  keystore: &Keystore,
  digest: &BigInt,
  signers_vec: &Vec<usize>,
  outgoing_sender: Sender<OutgoingMessages>,
  incoming_receiver: Receiver<IncomingMessages>,
) -> Result<(), CoreErrors> {
  log(&outgoing_sender, "Start signature generation".to_string())?;

  let (party_keys, shared_keys, _party_id, vss_scheme_vec, paillier_key_vector, y_sum): (
    &Keys,
    &SharedKeys,
    usize,
    &Vec<VerifiableSS>,
    &Vec<EncryptionKey>,
    &GE,
  ) = (
    &keystore.party_key,
    &keystore.shared_keys,
    keystore.party_index,
    &keystore.vss_scheme_vec,
    &keystore.paillier_key_vec,
    &keystore.y_sum,
  );

  let party_num_id = party_num_id as usize;
  let threshold = threshold as u16;
  let private = PartyPrivate::set_private(party_keys.clone(), shared_keys.clone());
  let sign_keys = SignKeys::create(
    &private,
    &vss_scheme_vec[signers_vec[party_num_id]],
    signers_vec[party_num_id],
    &signers_vec,
  );

  let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
  let (com, decommit) = sign_keys.phase1_broadcast();
  let m_a_k = MessageA::a(&sign_keys.k_i, &party_keys.ek);

  let msg = SignRound1Data {
    com: com.clone(),
    enc: m_a_k.clone(),
  };

  log(&outgoing_sender, "Broadcasting round 1".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_num_id as u8,
    &MessageData::SignRound1(msg.clone()),
  )?;

  log(&outgoing_sender, "Collecting data for round 1".to_string())?;
  let round_1 = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    msg,
    party_num_id as u8,
    participants,
  )?;

  // if round_1.is_err() {
  //   return err(&outgoing_sender, round_1.unwrap_err().into());
  // }
  // let round_1 = round_1.unwrap();

  let mut bc1_vec = round_1
    .iter()
    .map(|m| m.com.clone())
    .collect::<Vec<SignBroadcastPhase1>>();

  let mut m_a_vec = round_1
    .iter()
    .map(|m| m.enc.clone())
    .collect::<Vec<MessageA>>();

  m_a_vec.remove(party_num_id);

  let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
  let mut beta_vec: Vec<FE> = Vec::new();
  let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
  let mut ni_vec: Vec<FE> = Vec::new();
  let mut j = 0;
  for i in 0..=threshold as usize {
    if i != party_num_id {
      let (m_b_gamma, beta_gamma) = MessageB::b(
        &sign_keys.gamma_i,
        &paillier_key_vector[signers_vec[i]],
        m_a_vec[j].clone(),
      );
      let (m_b_w, beta_wi) = MessageB::b(
        &sign_keys.w_i,
        &paillier_key_vector[signers_vec[i]],
        m_a_vec[j].clone(),
      );
      m_b_gamma_send_vec.push(m_b_gamma);
      m_b_w_send_vec.push(m_b_w);
      beta_vec.push(beta_gamma);
      ni_vec.push(beta_wi);
      j += 1;
    }
  }

  log(&outgoing_sender, "Broadcasting round 2".to_string())?;

  let mut j = 0;
  for i in 0..=threshold as usize {
    if i != party_num_id {
      sendp2p(
        &outgoing_sender,
        i as u8,
        party_num_id as u8,
        &MessageData::SignRound2(SignRound2Data {
          g: m_b_gamma_send_vec[j].clone(),
          w: m_b_w_send_vec[j].clone(),
        }),
      )?;
      j += 1;
    }
  }

  // let round_2 =
  //   collect_round_others::<SignRound2Data>(&incoming_receiver, party_id as u8, participants);
  log(&outgoing_sender, "Collecting data for round 2".to_string())?;

  let mut round_2 = collect_round::<SignRound2Data>(
    &incoming_receiver,
    &outgoing_sender,
    SignRound2Data {
      g: m_b_gamma_send_vec[0].clone(),
      w: m_b_w_send_vec[0].clone(),
    },
    party_num_id as u8,
    participants,
  )?;

  // if round_2.is_err() {
  //   return err(&outgoing_sender, round_2.unwrap_err().into());
  // }
  // let mut round_2 = round_2.unwrap();
  round_2.remove(party_num_id);

  let m_b_gamma_rec_vec: Vec<MessageB> = round_2.iter().map(|m| m.g.clone()).collect();
  let m_b_w_rec_vec: Vec<MessageB> = round_2.iter().map(|m| m.w.clone()).collect();
  drop(round_2);

  let mut alpha_vec: Vec<FE> = Vec::new();
  let mut miu_vec: Vec<FE> = Vec::new();

  let mut j = 0;
  for i in 0..=threshold as usize {
    if i != party_num_id {
      let m_b = m_b_gamma_rec_vec[j].clone();
      let alpha_ij_gamma = m_b
        .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
        .map_err(|e| {
          CoreErrors::ExecutionIssue(format!(
            "Verifying of alpha proofs failed ({:?}) (gamma)",
            e
          ))
        })?;
      let m_b = m_b_w_rec_vec[j].clone();
      let alpha_ij_wi = m_b
        .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
        .map_err(|e| {
          CoreErrors::ExecutionIssue(format!("Verifying of alpha proofs failed ({:?}) (w)", e))
        })?;
      alpha_vec.push(alpha_ij_gamma);
      miu_vec.push(alpha_ij_wi);
      let g_w_i = Keys::update_commitments_to_xi(
        &xi_com_vec[signers_vec[i]],
        &vss_scheme_vec[signers_vec[i]],
        signers_vec[i],
        &signers_vec,
      );

      if m_b.b_proof.pk != g_w_i {
        return Err(CoreErrors::ExecutionIssue(format!(
          "proof point not equal to Gamma W"
        )));
      }

      j += 1;
    }
  }

  let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
  let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

  log(&outgoing_sender, "Broadcasting round 3".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_num_id as u8,
    &MessageData::SignRound3(delta_i.clone()),
  )?;

  log(&outgoing_sender, "Collecting data for round 3".to_string())?;
  let delta_vec = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    delta_i,
    party_num_id as u8,
    participants,
  )?;

  // if delta_vec.is_err() {
  //   return err(&outgoing_sender, delta_vec.unwrap_err().into());
  // }
  // let delta_vec = delta_vec.unwrap();

  let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

  log(&outgoing_sender, "Broadcasting round 4".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_num_id as u8,
    &MessageData::SignRound4(decommit.clone()),
  )?;

  log(&outgoing_sender, "Collecting data for round 4".to_string())?;

  let mut decommit_vec = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    decommit,
    party_num_id as u8,
    participants,
  )?;

  // if decommit_vec.is_err() {
  //   return err(&outgoing_sender, decommit_vec.unwrap_err().into());
  // }
  // let mut decommit_vec = decommit_vec.unwrap();
  let decomm_i = decommit_vec.remove(party_num_id);
  bc1_vec.remove(party_num_id);
  let b_proof_vec = (0..m_b_gamma_rec_vec.len())
    .map(|i| &m_b_gamma_rec_vec[i].b_proof)
    .collect::<Vec<&DLogProof>>();

  let r = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
    .map_err(|e| CoreErrors::ExecutionIssue(format!("Bad gamma_i decommit ({:?})", e)))?;
  let r = r + decomm_i.g_gamma_i * delta_inv;

  let message_bn = digest;

  let local_sig = LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &r, &sigma, &y_sum);

  let (phase5_com, phase_5a_decom, helgamal_proof) = local_sig.phase5a_broadcast_5b_zkproof();

  log(&outgoing_sender, "Broadcasting round 5".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_num_id as u8,
    &MessageData::SignRound5(phase5_com.clone()),
  )?;

  log(&outgoing_sender, "Collecting data for round 5".to_string())?;
  let mut commit5a_vec = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    phase5_com,
    party_num_id as u8,
    participants,
  )?;

  // if commit5a_vec.is_err() {
  //   return err(&outgoing_sender, commit5a_vec.unwrap_err().into());
  // }
  // let mut commit5a_vec = commit5a_vec.unwrap();

  let data = SignRound6Data {
    com: phase_5a_decom.clone(),
    proof: helgamal_proof.clone(),
  };

  log(&outgoing_sender, "Broadcasting round 6".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_num_id as u8,
    &MessageData::SignRound6(data.clone()),
  )?;

  log(&outgoing_sender, "Collecting data for round 6".to_string())?;
  let mut decommit5a_and_elgamal_vec = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    data,
    party_num_id as u8,
    participants,
  )?;

  // if decommit5a_and_elgamal_vec.is_err() {
  //   return err(
  //     &outgoing_sender,
  //     decommit5a_and_elgamal_vec.unwrap_err().into(),
  //   );
  // }
  // let mut decommit5a_and_elgamal_vec = decommit5a_and_elgamal_vec.unwrap();

  let decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_vec.clone();
  decommit5a_and_elgamal_vec.remove(party_num_id);
  commit5a_vec.remove(party_num_id);
  let phase_5a_decomm_vec = (0..threshold)
    .map(|i| decommit5a_and_elgamal_vec[i as usize].com.clone())
    .collect::<Vec<Phase5ADecom1>>();
  let phase_5a_elgamal_vec = (0..threshold)
    .map(|i| decommit5a_and_elgamal_vec[i as usize].proof.clone())
    .collect::<Vec<HomoELGamalProof>>();
  let (phase5_com2, phase_5d_decom2) = local_sig
    .phase5c(
      &phase_5a_decomm_vec,
      &commit5a_vec,
      &phase_5a_elgamal_vec,
      &phase_5a_decom.V_i,
      &r,
    )
    .map_err(|e| CoreErrors::ExecutionIssue(format!("Phase 5 failed ({:?})", e)))?;

  log(&outgoing_sender, "Broadcasting round 7".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_num_id as u8,
    &MessageData::SignRound7(phase5_com2.clone()),
  )?;
  log(&outgoing_sender, "Collecting data for round 7".to_string())?;
  let commit5c_vec = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    phase5_com2,
    party_num_id as u8,
    participants,
  )?;
  // if commit5c_vec.is_err() {
  //   return err(&outgoing_sender, commit5c_vec.unwrap_err().into());
  // }
  // let commit5c_vec = commit5c_vec.unwrap();

  log(&outgoing_sender, "Broadcasting round 8".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_num_id as u8,
    &MessageData::SignRound8(phase_5d_decom2.clone()),
  )?;

  log(&outgoing_sender, "Collecting data for round 8".to_string())?;
  let decommit5d_vec = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    phase_5d_decom2,
    party_num_id as u8,
    participants,
  )?;
  // if decommit5d_vec.is_err() {
  //   return err(&outgoing_sender, decommit5d_vec.unwrap_err().into());
  // }
  // let decommit5d_vec = decommit5d_vec.unwrap();
  let phase_5a_decomm_vec_includes_i = (0..=threshold)
    .map(|i| {
      decommit5a_and_elgamal_vec_includes_i[i as usize]
        .com
        .clone()
    })
    .collect::<Vec<Phase5ADecom1>>();

  let s_i = local_sig
    .phase5d(
      &decommit5d_vec,
      &commit5c_vec,
      &phase_5a_decomm_vec_includes_i,
    )
    .map_err(|e| {
      CoreErrors::ExecutionIssue(format!("Incorrect commitment at phase 5 ({:?})", e))
    })?;

  log(&outgoing_sender, "Broadcasting round 9".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_num_id as u8,
    &MessageData::SignRound9(s_i.clone()),
  )?;

  log(&outgoing_sender, "Collecting data for round 9".to_string())?;
  let mut s_i_vec = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    s_i,
    party_num_id as u8,
    participants,
  )?;

  // if s_i_vec.is_err() {
  //   return err(&outgoing_sender, s_i_vec.unwrap_err().into());
  // }
  // let mut s_i_vec = s_i_vec.unwrap();

  s_i_vec.remove(party_num_id);

  let sig = local_sig
    .output_signature(&s_i_vec)
    .map_err(|e| CoreErrors::ExecutionIssue(format!("Signature verification failed ({:?})", e)))?;

  outgoing_sender
    .send(OutgoingMessages::make_complete_signature(sig))
    .map_err(|e| CoreErrors::TransportIssue(format!("Failed sending result {}", e)))?;

  outgoing_sender
    .send(OutgoingMessages::Quit)
    .map_err(|e| CoreErrors::TransportIssue(format!("Failed sending quit {}", e)))?;

  Ok(())
}

pub fn keygeneration(
  participants: u8,
  threshold: u8,
  party_id: u8,
  outgoing_sender: Sender<OutgoingMessages>,
  incoming_receiver: Receiver<IncomingMessages>,
) {
  if let Err(e) = safe_keygeneration(
    participants,
    threshold,
    party_id,
    outgoing_sender.clone(),
    incoming_receiver,
  ) {
    outgoing_sender.send(OutgoingMessages::Log(format!("Error: {}", e)));
    outgoing_sender.send(OutgoingMessages::Error(Errors::Halted));
  }
}
pub fn safe_keygeneration(
  participants: u8,
  threshold: u8,
  party_id: u8,
  outgoing_sender: Sender<OutgoingMessages>,
  incoming_receiver: Receiver<IncomingMessages>,
) -> Result<(), CoreErrors> {
  let parties: u16 = participants as u16;
  let threshold: u16 = threshold as u16;

  let params = Parameters {
    threshold: threshold,
    share_count: parties,
  };

  let party_num_int = (party_id + 1) as u16;
  let party_keys = Keys::create(party_num_int as usize);
  let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

  log(&outgoing_sender, "Broadcasting round 1".to_string())?;

  broadcast(
    &outgoing_sender,
    participants,
    party_id,
    &MessageData::KeyGenRound1(bc_i.clone()),
  )?;

  log(&outgoing_sender, "Start collecting round 1".to_string())?;

  let bc1_vec = collect_round::<KeyGenBroadcastMessage1>(
    &incoming_receiver,
    &outgoing_sender,
    bc_i,
    party_id,
    participants,
  )?;

  // if bc1_vec.is_err() {
  //   return err(&outgoing_sender, bc1_vec.unwrap_err().into());
  // }
  // let bc1_vec = bc1_vec.unwrap();

  log(&outgoing_sender, "End of collecting round 1".to_string())?;

  log(&outgoing_sender, "Broadcasting round 2".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_id,
    &MessageData::KeyGenRound2(decom_i.clone()),
  )?;

  log(&outgoing_sender, "Collecting round 2".to_string())?;
  let decom_vec = collect_round::<KeyGenDecommitMessage1>(
    &incoming_receiver,
    &outgoing_sender,
    decom_i,
    party_id,
    participants,
  )?;
  // if decom_vec.is_err() {
  //   return err(&outgoing_sender, decom_vec.unwrap_err().into());
  // }
  // let decom_vec = decom_vec.unwrap();
  let point_vec: Vec<GE> = decom_vec.iter().map(|d| d.y_i).collect();
  let enc_keys: Vec<BigInt> = decom_vec
    .iter()
    .enumerate()
    .filter(|(k, _)| *k != party_id as usize)
    .map(|(_, d)| (d.y_i * party_keys.u_i).x_coor().unwrap())
    .collect();

  let (head, tail) = point_vec.split_at(1);
  let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

  let (vss_scheme, secret_shares, _index) = party_keys
    .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(&params, &decom_vec, &bc1_vec)
    .map_err(|e| CoreErrors::ExecutionIssue(format!("Invalid key at phase 2 ({:?})", e)))?;

  let mut j = 0;
  for (k, i) in (1..=parties).enumerate() {
    if i != party_num_int {
      // prepare encrypted ss for party i:
      let key_i = BigInt::to_vec(&enc_keys[j]);
      let plaintext = BigInt::to_vec(&secret_shares[k].to_big_int());
      let aead_pack_i = aes_encrypt(&key_i, &plaintext);
      log(&outgoing_sender, format!("Sending round 3 to {}", k))?;
      sendp2p(
        &outgoing_sender,
        k as u8,
        party_id,
        &MessageData::KeyGenRound3(aead_pack_i),
      )?;

      j += 1;
    }
  }

  log(&outgoing_sender, "Collecting round 3".to_string())?;
  let mut encrypted = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    AEAD::default(),
    party_id,
    participants,
  )?;
  // if encrypted.is_err() {
  //   return err(&outgoing_sender, encrypted.unwrap_err().into());
  // }
  // let mut encrypted = encrypted.unwrap();
  encrypted.remove(party_id as usize);

  let mut j = 0;
  let mut party_shares: Vec<FE> = Vec::new();
  for i in 1..=parties {
    if i == party_num_int {
      party_shares.push(secret_shares[(i - 1) as usize]);
    } else {
      let aead_pack: AEAD = encrypted[j].clone();
      let key_i = BigInt::to_vec(&enc_keys[j]);
      let out = aes_decrypt(&key_i, aead_pack);
      let out_bn = BigInt::from(&out[..]);
      let out_fe = ECScalar::from(&out_bn);
      party_shares.push(out_fe);

      j += 1;
    }
  }

  log(&outgoing_sender, "Broadcasting round 4".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_id,
    &MessageData::KeyGenRound4(vss_scheme.clone()),
  )?;

  log(&outgoing_sender, "Collecting round 4".to_string())?;
  let vss_scheme_vec = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    vss_scheme,
    party_id,
    participants,
  )?;
  // if vss_scheme_vec.is_err() {
  //   return err(&outgoing_sender, vss_scheme_vec.unwrap_err().into());
  // }
  // let vss_scheme_vec = vss_scheme_vec.unwrap();

  let (shared_keys, dlog_proof) = party_keys
    .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
      &params,
      &point_vec,
      &party_shares,
      &vss_scheme_vec,
      party_num_int as usize,
    )
    .map_err(|e| CoreErrors::ExecutionIssue(format!("Invalid vss ({:?})", e)))?;

  log(&outgoing_sender, "Broadcasting round 5".to_string())?;
  broadcast(
    &outgoing_sender,
    participants,
    party_id,
    &MessageData::KeyGenRound5(dlog_proof.clone()),
  )?;

  log(&outgoing_sender, "Collecting round 5".to_string())?;
  let dlog_proof_vec = collect_round(
    &incoming_receiver,
    &outgoing_sender,
    dlog_proof,
    party_id,
    participants,
  )?;
  // if dlog_proof_vec.is_err() {
  //   return err(&outgoing_sender, dlog_proof_vec.unwrap_err().into());
  // }
  // let dlog_proof_vec = dlog_proof_vec.unwrap();

  Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec)
    .map_err(|e| CoreErrors::ExecutionIssue(format!("Incorrect DLog proof ({:?})", e)))?;

  let paillier_key_vec = (0..parties)
    .map(|i| bc1_vec[i as usize].e.clone())
    .collect::<Vec<EncryptionKey>>();

  log(&outgoing_sender, "Send result".to_string())?;
  outgoing_sender
    .send(OutgoingMessages::make_complete_keygen(&Keystore {
      params: KeystoreParameters {
        threshold: params.threshold as u16,
        share_count: params.share_count as u16,
      },
      party_key: party_keys,
      party_shares,
      shared_keys,
      party_index: party_id as usize,
      vss_scheme_vec,
      paillier_key_vec,
      y_sum,
    }))
    .map_err(|e| CoreErrors::TransportIssue(format!("Failed sending result {}", e)))?;

  log(&outgoing_sender, "Send quit".to_string())?;

  outgoing_sender
    .send(OutgoingMessages::Quit)
    .map_err(|e| CoreErrors::TransportIssue(format!("Failed sending quit {}", e)))?;

  Ok(())
}

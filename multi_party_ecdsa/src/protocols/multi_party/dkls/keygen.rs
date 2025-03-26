/*
    This file is part of OpenTSS.
    Copyright (C) 2022 LatticeX Foundation.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
//! Implement keygen algorithm of multi-party ECDSA in dmz

use std::{collections::HashMap, sync::{Arc, Mutex}};

use crate::communication::sending_messages::SendingMessages;
use anyhow::anyhow;
use dkls23::{protocols::Parameters, utilities::rng::get_rng};
use dkls23_ll::dkg::{KeygenMsg1,KeygenMsg2, KeygenMsg3,KeygenMsg4, Party, State};
use serde::{Deserialize, Serialize};

/// Messages of each round in keygen
#[derive(Clone)]
pub struct KeyGenMsgs {
    pub phase_one_msgs: HashMap<String, KeygenMsg1>,
    pub phase_two_msgs: HashMap<String, KeygenMsg2>,
    pub phase_three_msgs: HashMap<String, KeygenMsg3>,
    pub phase_commitments: HashMap<String, [u8; 32]>,
    pub phase_four_msgs: HashMap<String, KeygenMsg4>,
}

#[derive(Clone, Debug)]
pub struct KeyGenMsgsFlag {
    pub phase_one_msgs: u8,
    pub phase_two_msgs: u8,
    pub phase_three_msgs: u8,
    pub phase_four_msgs: u8,
}

/// Key generation struct
pub struct KeyGenPhase {
    pub party_index: String,
    pub party_ids: Vec<String>,
    pub params: Parameters,
    pub party: State,
    // pub ec_keypair: EcKeyPair,
    // pub cl_keypair: ClKeyPair,
    // pub h_caret: PK,
    // pub private_signing_key: EcKeyPair,        // (u_i, u_iP)
    // pub public_signing_key: GE,                // Q
    // pub share_private_key: FE,                 // x_i
    // pub share_public_key: HashMap<String, GE>, // X_i
    pub msgs: KeyGenMsgs,
    pub msgsf: KeyGenMsgsFlag,
    // pub dlog_com: DlogCommitment,
    pub mutex: Arc<Mutex<usize>>,
}

impl KeyGenMsgs {
    pub fn new() -> Self {
        Self {
            phase_one_msgs: HashMap::new(),
            phase_two_msgs: HashMap::new(),
            phase_three_msgs: HashMap::new(),
            phase_four_msgs: HashMap::new(),
            phase_commitments: HashMap::new(),
        }
    }

    pub fn clean(&mut self) {
        self.phase_one_msgs.clear();
        self.phase_two_msgs.clear();
        self.phase_three_msgs.clear();
        self.phase_four_msgs.clear();
    }
}

impl KeyGenMsgsFlag {
    pub fn new() -> Self {
        Self {
            phase_one_msgs: 0,
            phase_two_msgs: 0,
            phase_three_msgs: 0,
            phase_four_msgs: 0,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum KeyGenWrapper {
    PhaseOne(KeygenMsg1),
    PhaseTwo(KeygenMsg2),
    PhaseThree(KeygenMsg3, [u8; 32]),
    PhaseFour(KeygenMsg4),
}

impl KeyGenPhase {
    /// partyid: The party id(index). Hex-string. (0, the modulus of the curve)
    /// params: t,n. t>0, n>t.
    /// party_ids: The list of parties whose size is equal to params.n.
    pub fn new(
        partyid: String,
        params: Parameters,
        party_ids: &Option<Vec<String>>,
    ) -> Result<Self, anyhow::Error> {
        // todo: remove the Option for party_ids in the future
        if *party_ids == None {
            return Err(anyhow!("party_ids is none"));
        }
        
        Ok(Self {
            party_index: partyid.clone(),
            party_ids: (*party_ids).clone().unwrap(),
            params: params.clone(),
            party: State::new(Party::new(params.share_count as usize, params.threshold as usize, partyid.parse::<usize>().unwrap()), &mut get_rng()),
            msgs: KeyGenMsgs::new(),
            msgsf: KeyGenMsgsFlag::new(),
            mutex: Arc::new(Mutex::new(0)),
        })
    }

     /// Handle message received and generate next round message.
    /// Return a result or the message to be sent in the next round.
    ///
    /// When a message is received, the processing is as follows:
    ///   If this message already exists, do nothing; otherwise, insert it into the cache.
    ///   When all the necessary messages have been received, generate the result or the next round of messages.
    pub fn msg_handler(
        &mut self,
        index: String,
        recv_msg: &Vec<u8>,
    ) -> Result<SendingMessages, anyhow::Error> {

        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();


        let msg:KeyGenWrapper = bincode::deserialize(recv_msg)?;
        match msg {
            KeyGenWrapper::PhaseOne(msg) => {

                self.msgs.phase_one_msgs.insert(index, msg);

                if self.msgs.phase_one_msgs.len() == self.party_ids.len() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                let mgs2 = self.party.handle_msg1(&mut get_rng(), self.msgs.phase_one_msgs.clone().into_values().collect::<Vec<KeygenMsg1>>()).unwrap();

                let mut hash_map = HashMap::new();

                for msg in mgs2 {
                    hash_map.insert(format!("{}", msg.to_id), bincode::serialize(&KeyGenWrapper::PhaseTwo(msg)).unwrap());
                }

                return Ok(SendingMessages::P2pMessage(hash_map));
            }
            KeyGenWrapper::PhaseTwo(msg) => {
                self.msgs.phase_two_msgs.insert(msg.from_id.to_string(), msg);

                if self.msgs.phase_two_msgs.len() == self.party_ids.len() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                let msgs2_received = self.msgs.phase_two_msgs.clone().into_values().collect::<Vec<KeygenMsg2>>();

                let mgs3 = self.party.handle_msg2(&mut get_rng(), msgs2_received).unwrap();

                let commitment = self.party.calculate_commitment_2();

                self.msgs.phase_commitments.insert(self.party_index.clone(), commitment);

                let mut hash_map = HashMap::new();

                for msg in mgs3 {
                    hash_map.insert(format!("{}", msg.to_id), bincode::serialize(&KeyGenWrapper::PhaseThree(msg, commitment)).unwrap());
                }

                return Ok(SendingMessages::P2pMessage(hash_map));
            }
            KeyGenWrapper::PhaseThree(msg, commitment) => {
                self.msgs.phase_commitments.insert(msg.from_id.to_string(), commitment);

                if self.msgs.phase_commitments.len() == self.party_ids.len() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                let mgs4 = self.party.handle_msg3(&mut get_rng(), vec![msg], &self.msgs.phase_commitments.values().copied().collect::<Vec<[u8; 32]>>()).unwrap();

               return Ok(SendingMessages::BroadcastMessage(bincode::serialize(&KeyGenWrapper::PhaseFour(mgs4)).unwrap()));
            }
            KeyGenWrapper::PhaseFour(msg) => {
                self.msgs.phase_four_msgs.insert(self.party_index.clone(), msg);

                if self.msgs.phase_four_msgs.len() == self.party_ids.len() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                let msgs4_received = self.msgs.phase_four_msgs.clone().into_values().collect::<Vec<KeygenMsg4>>();
                let final_share = self.party.handle_msg4(msgs4_received).unwrap();

                return Ok(SendingMessages::KeyGenSuccessWithResult(serde_json::to_string(&final_share).unwrap()))
            }
        }
    }

    pub fn process_begin(&mut self) -> Result<SendingMessages, anyhow::Error> {
        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();

        Ok(SendingMessages::BroadcastMessage(bincode::serialize(&KeyGenWrapper::PhaseOne(self.party.generate_msg1())).unwrap()))
    }



}
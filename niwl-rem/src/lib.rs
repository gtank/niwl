use crate::MixMessage::{Forward, Heartbeat};
use chrono::{DateTime, Duration, Local, NaiveDateTime};
use fuzzytags::{RootSecret, Tag, TaggingKey};
use niwl::encrypt::{PrivateKey, TaggedCiphertext};
use niwl::Profile;
use serde::{Deserialize, Serialize};
use std::fmt::Error;

#[derive(Serialize, Deserialize)]
pub enum MixMessage {
    Heartbeat(Tag<24>, DateTime<Local>),
    Forward(TaggedCiphertext),
}

pub struct RandomEjectionMix {
    heartbeat_id: Tag<24>,
}

impl RandomEjectionMix {
    pub fn init(tag: Tag<24>) -> RandomEjectionMix {
        RandomEjectionMix { heartbeat_id: tag }
    }

    pub fn push(&mut self, tag: &Tag<24>, plaintext: &String) -> Option<MixMessage> {
        // The plaintext can either be a TaggedCiphertext OR a HeartBeat
        let message: serde_json::Result<TaggedCiphertext> =
            serde_json::from_str(plaintext.as_str());
        match &message {
            Ok(ciphertext) => return Some(Forward(self.random_ejection_mix(ciphertext))),
            Err(_) => {
                // Assume this is a Mix Message
                let message: serde_json::Result<MixMessage> =
                    serde_json::from_str(plaintext.as_str());
                match &message {
                    Ok(mixMessage) => match mixMessage {
                        Heartbeat(id, time) => self.process_heartbeat(id, time),
                        _ => None,
                    },
                    Err(_) => None,
                }
            }
        }
    }

    fn process_heartbeat(&self, tag: &Tag<24>, heartbeat: &DateTime<Local>) -> Option<MixMessage> {
        if tag == &self.heartbeat_id {
            println!("Received HeartBeat @ {}", heartbeat);
            let new_heartbeat = Heartbeat(self.heartbeat_id.clone(), Local::now());
            return Some(new_heartbeat);
        }
        None
    }

    // Actually do the Random Ejection Mixing...
    fn random_ejection_mix(&mut self, ciphertext: &TaggedCiphertext) -> TaggedCiphertext {
        ciphertext.clone()
    }
}

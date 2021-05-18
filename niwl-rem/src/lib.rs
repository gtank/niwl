use crate::MixMessage::{Forward, Heartbeat};
use chrono::{DateTime, Duration, Local, NaiveDateTime};
use fuzzytags::{RootSecret, Tag, TaggingKey};
use niwl::encrypt::{PrivateKey, TaggedCiphertext};
use niwl::Profile;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt::Error;

#[derive(Serialize, Deserialize)]
pub enum MixMessage {
    Heartbeat(Tag<24>, DateTime<Local>),
    Forward(TaggedCiphertext),
}

pub struct RandomEjectionMix {
    heartbeat_id: Tag<24>,
    last_heartbeat: DateTime<Local>,
    store: Vec<TaggedCiphertext>,
}

impl RandomEjectionMix {
    pub fn init(tag: Tag<24>) -> RandomEjectionMix {
        let mut store = vec![];
        for i in 0..10 {
            store.push(RandomEjectionMix::get_random());
        }

        RandomEjectionMix {
            heartbeat_id: tag,
            last_heartbeat: Local::now(),
            store,
        }
    }

    pub fn get_random() -> TaggedCiphertext {
        let random_tag = RootSecret::<24>::generate().tagging_key().generate_tag();
        let random_secret = PrivateKey::generate();
        let random_encryption = random_secret
            .public_key()
            .encrypt(&random_tag, &String::new());
        random_encryption
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

    fn process_heartbeat(
        &mut self,
        tag: &Tag<24>,
        heartbeat: &DateTime<Local>,
    ) -> Option<MixMessage> {
        if tag == &self.heartbeat_id {
            println!("[DEBUG] Received HeartBeat from {}", heartbeat);
            self.last_heartbeat = heartbeat.clone();
            let now = Local::now();
            let new_heartbeat = Heartbeat(self.heartbeat_id.clone(), now.clone());
            return Some(new_heartbeat);
        }
        None
    }

    pub fn check_heartbeat(&self) -> bool {
        let time_since_last = Local::now() - self.last_heartbeat;
        println!(
            "[DEBUG] Time since last heartbeat: {}s",
            time_since_last.num_seconds()
        );
        if time_since_last > Duration::minutes(2) {
            return false;
        }
        return true;
    }

    // Actually do the Random Ejection Mixing...
    fn random_ejection_mix(&mut self, ciphertext: &TaggedCiphertext) -> TaggedCiphertext {
        let mut rng = OsRng::default();
        let random_index = rng.gen_range(0..10);
        println!("[DEBUG] Ejecting {} ", random_index);
        let ejection = self.store[random_index].clone();
        self.store[random_index] = ciphertext.clone();
        ejection
    }
}

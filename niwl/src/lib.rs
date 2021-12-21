#![feature(into_future)]
use crate::encrypt::{PrivateKey, PublicKey, TaggedCiphertext};
use fuzzytags::{DetectionKey, RootSecret, Tag, TaggingKey};
use rand::rngs::OsRng;
use reqwest::{Error, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Write;

pub mod encrypt;

#[derive(Debug)]
pub enum NiwlError {
    NoKnownContactError(String),
    RemoteServerError(String),
}

#[derive(Serialize, Deserialize)]
pub struct Profile {
    profile_name: String,
    pub root_secret: RootSecret<24>,
    pub private_key: PrivateKey,
    tagging_keys: HashMap<String, (TaggingKey<24>, PublicKey)>,
    detection_key_length: usize,
    last_seen_tag: Option<Tag<24>>,
}

#[derive(Serialize, Deserialize)]
pub struct KeySet {
    profile_name: String,
    tagging_key: TaggingKey<24>,
    public_key: PublicKey,
}

#[derive(Deserialize)]
pub struct DetectedTags {
    pub detected_tags: Vec<(Tag<24>, TaggedCiphertext)>,
}

#[derive(Serialize, Deserialize)]
pub struct FetchMessagesRequest {
    // The last tag this client downloaded to use as a reference when fetching new messages
    // If None, then the server will check *all* messages.
    pub reference_tag: Option<Tag<24>>,
    // The detection key to use to fetch new messages
    pub detection_key: DetectionKey<24>,
}

#[derive(Serialize, Deserialize)]
pub struct PostMessageRequest {
    pub tag: Tag<24>,
    pub ciphertext: TaggedCiphertext,
}

impl Profile {
    pub fn get_profile(profile_filename: &String) -> Profile {
        match fs::read_to_string(profile_filename) {
            Ok(json) => serde_json::from_str(json.as_str()).unwrap(),
            Err(why) => {
                panic!("couldn't read orb.profile : {}", why);
            }
        }
    }

    pub fn new(profile_name: String, detection_key_length: usize) -> Profile {
        let root_secret = RootSecret::<24>::generate(&mut OsRng);
        let private_key = PrivateKey::generate();
        Profile {
            profile_name,
            root_secret,
            private_key,
            tagging_keys: Default::default(),
            detection_key_length,
            last_seen_tag: None,
        }
    }

    pub fn keyset(&self) -> KeySet {
        let tagging_key = self.root_secret.tagging_key();
        let public_key = self.private_key.public_key();
        KeySet {
            profile_name: self.profile_name.clone(),
            tagging_key,
            public_key,
        }
    }

    pub fn save(&self, profile_filename: &String) -> std::io::Result<()> {
        let j = serde_json::to_string(&self);
        let mut file = match File::create(profile_filename) {
            Err(why) => panic!("couldn't create : {}", why),
            Ok(file) => file,
        };
        file.write_all(j.unwrap().as_bytes())
    }

    pub fn generate_tag(&self, id: &String) -> Result<Tag<24>, NiwlError> {
        if self.tagging_keys.contains_key(id) {
            let tag = self.tagging_keys[id].0.generate_tag(&mut OsRng);
            println!("Tag for {} {}", id, tag.to_string());
            return Ok(tag);
        }
        Err(NiwlError::NoKnownContactError(format!(
            "No known friend {}. Perhaps you need to import-tagging-key first?",
            id
        )))
    }

    pub fn import_tagging_key(&mut self, key: &String) {
        match base32::decode(base32::Alphabet::RFC4648 { padding: false }, key.as_str()) {
            Some(data) => {
                let tagging_key_result: Result<KeySet, bincode::Error> =
                    bincode::deserialize(&data);
                match tagging_key_result {
                    Ok(hotk) => {
                        println!("Got: {}: {}", hotk.profile_name, hotk.tagging_key.id());
                        if self.tagging_keys.contains_key(&hotk.profile_name) == false {
                            self.tagging_keys
                                .insert(hotk.profile_name, (hotk.tagging_key, hotk.public_key));
                        } else {
                            println!("There is already an entry for {}", hotk.profile_name)
                        }
                        return;
                    }
                    Err(err) => {
                        println!("Error: {}", err.to_string());
                    }
                }
            }
            _ => {}
        };
        println!("Error Reporting Tagging Key")
    }

    pub async fn tag_and_mix(
        &self,
        server: String,
        mix: String,
        contact: String,
        message: &String,
    ) -> Result<Response, NiwlError> {
        match self.generate_tag(&contact) {
            Ok(tag) => {
                let ciphertext = self.tagging_keys[&contact].1.encrypt(&tag, message);
                let ciphertext_json = serde_json::to_string(&ciphertext).unwrap();
                return self.tag_and_send(&server, mix, &ciphertext_json).await;
            }
            Err(err) => Err(err),
        }
    }

    pub async fn send_to_self(
        &self,
        server: &String,
        message: &String,
    ) -> Result<Response, NiwlError> {
        let client = reqwest::Client::new();
        let tag = self.root_secret.tagging_key().generate_tag(&mut OsRng);
        let ciphertext = self.private_key.public_key().encrypt(&tag, message);

        let result = client
            .post(&format!("{}/new", server))
            .json(&PostMessageRequest { tag, ciphertext })
            .send()
            .await;
        match result {
            Ok(response) => Ok(response),
            Err(err) => Err(NiwlError::RemoteServerError(err.to_string())),
        }
    }

    pub async fn forward(
        &self,
        server: &String,
        message: &TaggedCiphertext,
    ) -> Result<Response, NiwlError> {
        let client = reqwest::Client::new();
        let tag = message.tag.clone();
        let ciphertext = message.clone();

        let result = client
            .post(&format!("{}/new", server))
            .json(&PostMessageRequest { tag, ciphertext })
            .send()
            .await;
        match result {
            Ok(response) => Ok(response),
            Err(err) => Err(NiwlError::RemoteServerError(err.to_string())),
        }
    }

    pub async fn tag_and_send(
        &self,
        server: &String,
        contact: String,
        message: &String,
    ) -> Result<Response, NiwlError> {
        let client = reqwest::Client::new();
        match self.generate_tag(&contact) {
            Ok(tag) => {
                let ciphertext = self.tagging_keys[&contact].1.encrypt(&tag, message);

                let result = client
                    .post(&format!("{}/new", server))
                    .json(&PostMessageRequest { tag, ciphertext })
                    .send()
                    .await;
                match result {
                    Ok(response) => Ok(response),
                    Err(err) => Err(NiwlError::RemoteServerError(err.to_string())),
                }
            }
            Err(err) => Err(err),
        }
    }

    pub async fn detect_tags(&mut self, server: &String) -> Result<DetectedTags, Error> {
        let client = reqwest::Client::new();
        let detection_key = self
            .root_secret
            .extract_detection_key(self.detection_key_length);
        let result = client
            .post(&format!("{}/tags", server))
            .json(&FetchMessagesRequest {
                reference_tag: self.last_seen_tag.clone(),
                detection_key,
            })
            .send()
            .await;
        result.unwrap().json().await
    }

    pub fn update_previously_seen_tag(&mut self, tag: &Tag<24>) {
        self.last_seen_tag = Some(tag.clone());
    }
}

#![feature(into_future)]
use fuzzytags::{RootSecret, TaggingKey, Tag};
use std::fs::File;
use std::io::Write;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use reqwest::{Response, Error};
use std::future::{Future, IntoFuture};

#[derive(Debug)]
pub enum NiwlError {
    NoKnownContactError(String),
    RemoteServerError(String)
}

#[derive(Serialize,Deserialize)]
pub struct Profile {
    profile_name: String,
    root_secret: RootSecret<24>,
    tagging_keys: HashMap<String, TaggingKey<24>>,
}

#[derive(Serialize,Deserialize)]
pub struct HumanOrientedTaggingKey {
    profile_name: String,
    tagging_key: TaggingKey<24>,
}

#[derive(Deserialize)]
pub struct DetectedTags {
    pub detected_tags: Vec<Tag<24>>,
}

impl Profile {
    pub fn new(profile_name: String) -> Profile {
        let root_secret = RootSecret::<24>::generate();
        Profile {
            profile_name,
            root_secret,
            tagging_keys: Default::default()
        }
    }

    pub fn human_readable_tagging_key(&self) -> HumanOrientedTaggingKey {
        let tagging_key = self.root_secret.tagging_key();
        HumanOrientedTaggingKey {
            profile_name: self.profile_name.clone(),
            tagging_key
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
            let tag = self.tagging_keys[id].generate_tag();
            println!("Tag for {} {}", id, tag.to_string());
            return Ok(tag)
        }
        Err(NiwlError::NoKnownContactError(format!("No known friend {}. Perhaps you need to import-tagging-key first?", id)))
    }

    pub fn import_tagging_key(&mut self, key: &String) {
        match base32::decode(base32::Alphabet::RFC4648 { padding: false }, key.as_str()) {
            Some(data) => {
                let tagging_key_result: Result<HumanOrientedTaggingKey, bincode::Error> = bincode::deserialize(&data);
                match tagging_key_result {
                    Ok(hotk) => {
                        println!("Got: {}: {}", hotk.profile_name, hotk.tagging_key.id());
                        if self.tagging_keys.contains_key(&hotk.profile_name) == false {
                            self.tagging_keys.insert(hotk.profile_name, hotk.tagging_key);
                        } else {
                            println!("There is already an entry for {}", hotk.profile_name)
                        }
                        return
                    }
                    Err(err) => {
                        println!("Error: {}", err.to_string());
                    }
                }
            },
            _ => {}
        };
        println!("Error Reporting Tagging Key")
    }

    pub async fn tag_and_send(&self, server: String, contact: String) -> Result<Response, NiwlError> {
        let client = reqwest::Client::new();
        match self.generate_tag(&contact) {
            Ok(tag) => {
                let result = client.
                    post(&String::from(server + "/new"))
                    .json(&tag)
                    .send().await;
                match result {
                    Ok(response) => Ok(response),
                    Err(err) => Err(NiwlError::RemoteServerError(err.to_string()))
                }
            }
            Err(err) => {
                Err(err)
            }
        }
    }

    pub async fn detect_tags(&mut self, server: String) -> Result<DetectedTags, Error> {
        let client = reqwest::Client::new();
        let detection_key = self.root_secret.extract_detection_key(1);
        let result = client.post(&String::from(server + "/tags"))
            .json(&detection_key)
            .send().await;
        result.unwrap().json().await
    }
}
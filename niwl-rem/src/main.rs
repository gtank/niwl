use chrono::Local;
use clap::Clap;
use niwl::Profile;
use niwl_rem::MixMessage::Heartbeat;
use niwl_rem::{MixMessage, RandomEjectionMix};
use std::time::Duration;

#[derive(Clap)]
#[clap(version = "1.0", author = "Sarah Jamie Lewis <sarah@openprivacy.ca>")]
struct Opts {
    #[clap(default_value = "niwl.profile")]
    profile_filename: String,

    #[clap(default_value = "http://localhost:8000")]
    niwl_server: String,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Generate(Generate),
    Run(Run),
}

/// Generate a new niwl.profile file
#[derive(Clap)]
struct Generate {
    name: String,
}

/// Run a Random Ejection Mix
#[derive(Clap)]
struct Run {}

fn main() {
    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Generate(g) => {
            let profile = Profile::new(g.name.clone(), 0);
            let hotk = profile.keyset();
            println!(
                "Tagging Key: {}",
                base32::encode(
                    base32::Alphabet::RFC4648 { padding: false },
                    bincode::serialize(&hotk).unwrap().as_slice()
                )
                .to_ascii_lowercase()
            );
            profile.save(&opts.profile_filename);
        }
        SubCommand::Run(_cmd) => {
            let mut profile = Profile::get_profile(&opts.profile_filename);
            let server = opts.niwl_server.clone();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let random_tag = profile.root_secret.tagging_key().generate_tag();
                    let mut rem = RandomEjectionMix::init(random_tag.clone());
                    println!("kicking off initial heartbeat...");
                    profile
                        .send_to_self(
                            &server,
                            &serde_json::to_string(&Heartbeat(random_tag.clone(), Local::now()))
                                .unwrap(),
                        )
                        .await;
                    println!("starting..");
                    let detection_key = profile.root_secret.extract_detection_key(24);

                    loop {
                        match profile.detect_tags(&server).await {
                            Ok(detected_tags) => {
                                let mut latest_tag = None;
                                for (tag, ciphertext) in detected_tags.detected_tags.iter() {
                                    if detection_key.test_tag(&tag) {
                                        let plaintext = profile.private_key.decrypt(ciphertext);
                                        match plaintext {
                                            Some(plaintext) => match rem.push(tag, &plaintext) {
                                                None => {}
                                                Some(message) => {
                                                    let response = match &message {
                                                        MixMessage::Heartbeat(_, _) => {
                                                            profile
                                                                .send_to_self(
                                                                    &server,
                                                                    &serde_json::to_string(
                                                                        &message,
                                                                    )
                                                                    .unwrap(),
                                                                )
                                                                .await
                                                        }
                                                        MixMessage::Forward(ciphertext) => {
                                                            profile
                                                                .forward(&server, ciphertext)
                                                                .await
                                                        }
                                                    };

                                                    match response {
                                                        Err(err) => {
                                                            println!("[ERROR] {:?}", err);
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            },
                                            _ => {}
                                        }
                                    }
                                    latest_tag = Some(tag.clone());
                                }
                                println!("Updating...");
                                match &latest_tag {
                                    Some(tag) => {
                                        profile.update_previously_seen_tag(tag);
                                    }
                                    _ => {}
                                }
                            }
                            Err(err) => {
                                println!("Error: {}", err)
                            }
                        }
                        println!("sleeping..");
                        tokio::time::sleep(Duration::new(5, 0)).await;
                    }
                });
        }
    }
}

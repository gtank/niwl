use chrono::Local;
use clap::Clap;
use niwl::Profile;
use niwl_rem::MixMessage::Heartbeat;
use niwl_rem::{MixMessage, RandomEjectionMix};
use rand::{thread_rng, Rng};
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
            let filename = opts.profile_filename.clone();
            let server = opts.niwl_server.clone();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let random_tag = profile.root_secret.tagging_key().generate_tag();
                    let mut rem = RandomEjectionMix::init(random_tag.clone());
                    println!("[DEBUG] kicking off initial heartbeat...");
                    profile
                        .send_to_self(
                            &server,
                            &serde_json::to_string(&Heartbeat(random_tag.clone(), Local::now()))
                                .unwrap(),
                        )
                        .await;
                    println!("[DEBUG] starting mixing loop");
                    let detection_key = profile.root_secret.extract_detection_key(24);

                    loop {


                        if rem.check_heartbeat() == false {
                            println!("[ERROR] Niwl Server is Delaying Messages for more than 2 Minutes...Possible Attack...");
                            let num_messages : i32 = thread_rng().gen_range(0..100);
                            // Kick out a random number of messages...
                            for i in 0..num_messages {
                                random_delay();
                                profile.send_to_self(&server, &serde_json::to_string(
                                    &RandomEjectionMix::get_random(),
                                ).unwrap()).await;
                            }
                        } else {
                            // After every heart beat kick out a random
                            // message so we wil eventually clear the pool
                            random_delay();
                            profile.send_to_self(&server,&serde_json::to_string(
                                &RandomEjectionMix::get_random(),
                            ).unwrap()).await;

                        }


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
                                match &latest_tag {
                                    Some(tag) => {
                                        profile.update_previously_seen_tag(tag);
                                        profile.save(&filename);
                                    }
                                    _ => {}
                                }
                            }
                            Err(err) => {
                                println!("Error: {}", err)
                            }
                        }

                        random_delay().await;
                    }
                });
        }
    }
}

async fn random_delay() {
    let mut rng = rand::thread_rng();
    let seconds = rng.gen_range(0..10);
    let nanos = rng.gen_range(0..1_000_000_000);
    println!("[DEBUG] Waiting {}.{}s", seconds, nanos);
    tokio::time::sleep(Duration::new(seconds, nanos)).await;
}

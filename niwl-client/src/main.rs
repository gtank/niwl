use clap::Clap;
use niwl::Profile;

#[derive(Clap)]
#[clap(version = "1.0", author = "Sarah Jamie Lewis <sarah@openprivacy.ca>")]
struct Opts {
    #[clap(default_value = "niwl.profile")]
    profile: String,

    #[clap(default_value = "http://localhost:8000")]
    niwl_server: String,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Generate(Generate),
    ImportTaggingKey(ImportTaggingKey),
    TagAndSend(TagAndSend),
    TagAndMix(TagAndMix),
    Detect(Detect),
}

/// Generate a new niwl.profile file
#[derive(Clap)]
struct Generate {
    name: String,
    #[clap(default_value = "2")]
    length: usize,
}

/// Import a friends tagging key into this profile so you can send messages to them
#[derive(Clap)]
struct ImportTaggingKey {
    key: String,
}

/// Connect to a server and check for new notifications
#[derive(Clap)]
struct Detect {}

/// Send a message to a friend tagged with their niwl key
#[derive(Clap)]
struct TagAndSend {
    /// the id of the friend e.g. "alice"
    id: String,
    /// the message you want to send.
    message: String,
}

/// Send a message to a friend tagged with their niwl key
#[derive(Clap)]
struct TagAndMix {
    /// the id of the mix
    mix: String,
    /// the id of the friend e.g. "alice"
    id: String,
    /// the message you want to send.
    message: String,
}

fn main() {
    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Generate(g) => {
            let profile = Profile::new(g.name.clone(), g.length);
            let hotk = profile.keyset();
            println!(
                "Tagging Key: {}",
                base32::encode(
                    base32::Alphabet::RFC4648 { padding: false },
                    bincode::serialize(&hotk).unwrap().as_slice()
                )
                .to_ascii_lowercase()
            );
            match profile.save(&opts.profile) {
                Err(e) => {
                    println!("[ERROR] {}", e)
                }
                _ => {}
            }
        }
        SubCommand::ImportTaggingKey(cmd) => {
            let mut profile = Profile::get_profile(&opts.profile);
            profile.import_tagging_key(&cmd.key);
            match profile.save(&opts.profile) {
                Err(e) => {
                    println!("[ERROR] {}", e)
                }
                _ => {}
            }
        }
        SubCommand::TagAndSend(cmd) => {
            let profile = Profile::get_profile(&opts.profile);
            let server = opts.niwl_server.clone();
            let contact = cmd.id.clone();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let result = profile.tag_and_send(&server, contact, &cmd.message).await;
                    println!("{}", result.unwrap().text().await.unwrap());
                });
        }
        SubCommand::TagAndMix(cmd) => {
            let profile = Profile::get_profile(&opts.profile);
            let server = opts.niwl_server.clone();
            let contact = cmd.id.clone();
            let mix = cmd.mix.clone();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let result = profile
                        .tag_and_mix(server, mix, contact, &cmd.message)
                        .await;
                    println!("{}", result.unwrap().text().await.unwrap());
                });
        }
        SubCommand::Detect(_cmd) => {
            let mut profile = Profile::get_profile(&opts.profile);
            let server = opts.niwl_server.clone();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    match profile.detect_tags(&server).await {
                        Ok(detected_tags) => {
                            let mut count = 0;
                            let mut to_me_count = 0;
                            for (tag, ciphertext) in detected_tags.detected_tags.iter() {
                                count += 1;
                                match profile.private_key.decrypt(ciphertext) {
                                    Some(message) => {
                                        to_me_count += 1;
                                        println!("message: {}", message)
                                    }
                                    _ => {}
                                }
                                profile.update_previously_seen_tag(tag);
                            }
                            if count > 0 {
                                println!(
                                    "Received {} Messages from server. {} were true positives.",
                                    count, to_me_count
                                );
                            } else {
                                println!("Received no messages.");
                            }
                        }
                        Err(err) => {
                            println!("Error: {}", err)
                        }
                    }
                });

            match profile.save(&opts.profile) {
                Err(e) => {
                    println!("[ERROR] {}", e)
                }
                _ => {}
            }
        }
    }
}

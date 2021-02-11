use clap::Clap;
use std::fs;
use niwl::{Profile};

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
    ImportTaggingKey(ImportTaggingKey),
    TagAndSend(TagAndSend),
    Detect(Detect)
}

/// Generate a new niwl.profile file
#[derive(Clap)]
struct Generate {
    name: String
}

/// Import a friends tagging key into this profile so you can send messages to them
#[derive(Clap)]
struct ImportTaggingKey {
    key: String
}

/// Connect to a server and check for new notifications
#[derive(Clap)]
struct Detect {
    #[clap(default_value = "2")]
    length: u8
}

/// Send a message to a friend tagged with their niwl key
#[derive(Clap)]
struct TagAndSend {
    /// the id of the friend e.g. "alice"
    id: String,
    /// the message you want to send.
    message: String,
}

fn get_profile(profile_filename: &String) -> Profile {
     match fs::read_to_string(profile_filename) {
        Ok(json) => serde_json::from_str(json.as_str()).unwrap(),
        Err(why) => {
            panic!("couldn't read orb.profile : {}", why);
        }
    }
}



fn main() {
    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Generate(g) => {
            let profile = Profile::new(g.name.clone());
            let hotk = profile.human_readable_tagging_key();
            println!("Tagging Key: {}", base32::encode(base32::Alphabet::RFC4648{padding:false} ,bincode::serialize(&hotk).unwrap().as_slice()).to_ascii_lowercase());
            profile.save(&opts.profile_filename);
        }
        SubCommand::ImportTaggingKey(cmd) => {
            let mut profile = get_profile(&opts.profile_filename);
            profile.import_tagging_key(&cmd.key);
            profile.save(&opts.profile_filename);
        },
        SubCommand::TagAndSend(cmd) => {
            let mut profile = get_profile(&opts.profile_filename);
            let server = opts.niwl_server.clone();
            let contact = cmd.id.clone();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let result = profile.tag_and_send(server, contact).await;
                    println!("{}", result.unwrap().text().await.unwrap());
                });
        },
        SubCommand::Detect(cmd) => {
            let mut profile = get_profile(&opts.profile_filename);
            let server = opts.niwl_server.clone();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    match profile.detect_tags(server).await {
                        Ok(detected_tags) => {
                            for tag in detected_tags.detected_tags {
                                println!("{}", tag);
                            }
                        },
                        Err(err) => {
                            println!("Error: {}", err)
                        }
                    }
                });
        }
    }
}

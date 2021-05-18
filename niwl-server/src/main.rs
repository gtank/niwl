#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;

use fuzzytags::{DetectionKey, Tag};
use niwl::encrypt::TaggedCiphertext;
use niwl::{FetchMessagesRequest, PostMessageRequest};
use rocket_contrib::databases::rusqlite;
use rocket_contrib::databases::rusqlite::types::ToSql;
use rocket_contrib::json;
use rocket_contrib::json::{Json, JsonValue};

#[database("tags")]
struct TagsDbConn(rusqlite::Connection);

#[post("/new", format = "application/json", data = "<post_message_request>")]
fn new(conn: TagsDbConn, post_message_request: Json<PostMessageRequest>) -> JsonValue {
    match serde_json::to_string(&post_message_request.ciphertext) {
        Ok(ciphertext) => {
            match conn.0.execute(
                "INSERT INTO tags (tag, message) VALUES (?1, ?2);",
                &[
                    &post_message_request.tag.compress() as &dyn ToSql,
                    &ciphertext,
                ],
            ) {
                Ok(_) => {
                    json!({"tag" : post_message_request.tag.to_string()})
                }
                Err(_) => {
                    json!({"tag" : "error"})
                }
            }
        }
        _ => {
            json!({"tag" : "error"})
        }
    }
}

#[post("/tags", format = "application/json", data = "<fetch_message_request>")]
fn tags(conn: TagsDbConn, fetch_message_request: Json<FetchMessagesRequest>) -> JsonValue {
    let mut detected_tags: Vec<(Tag<24>, TaggedCiphertext)> = vec![];

    let mut select = conn
        .0
        .prepare("SELECT tag,message FROM tags WHERE id>(SELECT id FROM tags WHERE tag=(?));")
        .unwrap();

    let mut select_all = conn.0.prepare("SELECT tag,message FROM tags;").unwrap();

    let all = match &fetch_message_request.reference_tag {
        Some(tag) => {
            let mut stmt = conn
                .0
                .prepare("SELECT COUNT(*) FROM tags WHERE tag=(?);")
                .unwrap();
            let count = stmt.query_row(&[&tag.compress() as &dyn ToSql], |row| {
                let count: i32 = row.get(0);
                return count;
            });
            match count {
                Ok(count) => count == 0,
                _ => true,
            }
        }
        None => true,
    };

    match all {
        false => {
            let ref_tag = fetch_message_request.reference_tag.clone().unwrap();
            let selected_tags = select
                .query_map(&[&ref_tag.compress() as &dyn ToSql], |row| {
                    let tag_bytes: Vec<u8> = row.get(0);
                    let tag = Tag::<24>::decompress(tag_bytes.as_slice()).unwrap();

                    let ciphertext_json: String = row.get(1);
                    let message: TaggedCiphertext =
                        serde_json::from_str(ciphertext_json.as_str()).unwrap();
                    (tag, message)
                })
                .unwrap();
            for result in selected_tags {
                match result {
                    Ok((tag, ciphertext)) => {
                        if fetch_message_request.detection_key.test_tag(&tag) {
                            detected_tags.push((tag, ciphertext));
                        }
                    }
                    _ => {}
                }
            }
        }
        true => {
            let selected_tags = select_all
                .query_map(&[], |row| {
                    let tag_bytes: Vec<u8> = row.get(0);
                    let tag = Tag::<24>::decompress(tag_bytes.as_slice()).unwrap();

                    let ciphertext_json: String = row.get(1);
                    let message: TaggedCiphertext =
                        serde_json::from_str(ciphertext_json.as_str()).unwrap();
                    (tag, message)
                })
                .unwrap();
            for result in selected_tags {
                match result {
                    Ok((tag, ciphertext)) => {
                        if fetch_message_request.detection_key.test_tag(&tag) {
                            detected_tags.push((tag, ciphertext));
                        }
                    }
                    _ => {}
                }
            }
        }
    };

    json!({ "detected_tags": detected_tags })
}

fn main() {
    rocket::ignite()
        .attach(TagsDbConn::fairing())
        .mount("/", routes![tags, new])
        .launch();
}

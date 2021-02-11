#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;

use rocket_contrib::json;
use fuzzytags::{DetectionKey, Tag};
use rocket_contrib::json::{Json, JsonValue};
use rocket_contrib::databases::rusqlite;
use rocket_contrib::databases::rusqlite::types::ToSql;
use chrono::{Utc, Duration};
use std::ops::Sub;

#[database("tags")]
struct TagsDbConn(rusqlite::Connection);

#[post("/new", format = "application/json", data = "<tag>")]
fn new(conn:TagsDbConn, tag: Json<Tag<24>>) -> JsonValue {
    conn.0.execute(
        "INSERT INTO tags (id, tag) VALUES (strftime('%Y-%m-%d %H:%M:%S:%f', 'now'), ?1)",
        &[&tag.0.compress() as &dyn ToSql],
    ).unwrap();
    json!({"tag" : tag.to_string()})
}

#[post("/tags", format = "application/json", data = "<detection_key>")]
fn tags(conn:TagsDbConn, detection_key: Json<DetectionKey<24>>) -> JsonValue {

    let mut stmt = conn.0.prepare(
        "SELECT tag FROM tags WHERE id > (?1) AND id < (?2)",
    ).unwrap();

    let now = Utc::now();
    let after = now.sub(Duration::days(1)).format("%Y-%m-%d %H:%M:%S:%f").to_string();
    let before = now.format("%Y-%m-%d %H:%M:%S:%f").to_string();
    let selected_tags = stmt.query_map(&[&after, &before], |row| {
        let tag_bytes : Vec<u8> = row.get(0);
        let tag = Tag::<24>::decompress(tag_bytes.as_slice()).unwrap();
        tag
    }).unwrap();

    let mut detected_tags : Vec<Tag<24>> = vec![];
    for tag in selected_tags {
        let tag : Tag<24> = tag.unwrap();
        if detection_key.0.test_tag(&tag) {
            detected_tags.push(tag);
        }
    }

    json!({"detected_tags" : detected_tags})
}

fn main() {
    rocket::ignite().attach(TagsDbConn::fairing()).mount("/", routes![tags, new]).launch();
}

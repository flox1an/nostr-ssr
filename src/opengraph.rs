use crate::config::{Config, OpenGraph};
use crate::head::{absolute, escape_html};
use crate::media::{Media, IMAGE_KIND, OLD_SHORTS_KIND, OLD_VIDEO_KIND, SHORTS_KIND, VIDEO_KIND};
use crate::mirror::{parse_filter, Mirror};
use nostr::nips::nip19::{Nip19, Nip19Coordinate, Nip19Event};
use nostr::prelude::*;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const NIP05_TTL: Duration = Duration::from_secs(24 * 3600);
const NIP05_NEGATIVE_TTL: Duration = Duration::from_secs(600);
const NIP05_TIMEOUT: Duration = Duration::from_secs(5);
const ENTITY_PREFIXES: [&str; 5] = ["npub1", "nprofile1", "naddr1", "nevent1", "note1"];
const HINT_HOST_INTERVAL: Duration = Duration::from_secs(10);
const HINT_HOST_FAILURE_PAUSE: Duration = Duration::from_secs(600);
const HINT_CONCURRENCY: usize = 16;

#[derive(Default)]
pub struct State {
    nip05: Mutex<HashMap<String, (Instant, Option<PublicKey>)>>,
    client: reqwest::Client,
    hints: Arc<HintLimits>,
}

#[derive(Default)]
struct HintLimits {
    hosts: Mutex<HashMap<String, Instant>>,
    in_flight: AtomicUsize,
    allow_private: bool,
}

fn host_of(url: &RelayUrl) -> String {
    reqwest::Url::parse(url.as_str()).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default()
}

impl HintLimits {
    fn claim(&self, url: &RelayUrl) -> bool {
        let now = Instant::now();
        let mut hosts = self.hosts.lock().unwrap();
        hosts.retain(|_, until| *until > now);
        let host = host_of(url);
        if hosts.contains_key(&host) || self.in_flight.load(Ordering::Acquire) >= HINT_CONCURRENCY {
            return false;
        }
        hosts.insert(host, now + HINT_HOST_INTERVAL);
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        true
    }

    fn release(&self, url: &RelayUrl, failed: bool) {
        if failed {
            self.hosts.lock().unwrap().insert(host_of(url), Instant::now() + HINT_HOST_FAILURE_PAUSE);
        }
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Tags {
    pub metas: Vec<(String, String)>,
    pub title: Option<String>,
    pub canonical: Option<String>,
    pub json_ld: Option<String>,
    pub author: Option<PublicKey>,
    pub oembed: Option<String>,
}

pub struct Profile {
    pub name: Option<String>,
    pub about: Option<String>,
    pub picture: Option<String>,
}

fn avatar(og: &OpenGraph, pubkey: &PublicKey) -> String {
    og.avatar.replace("{pubkey}", &pubkey.to_hex())
}

fn tag_value<'a>(ev: &'a Event, name: &str) -> Option<&'a str> {
    ev.tags.iter().find(|t| t.as_slice().first().map(String::as_str) == Some(name)).and_then(|t| t.as_slice().get(1)).map(String::as_str)
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn last_segment(path: &str) -> Option<&str> {
    path.split(['?', '#']).next()?.trim_end_matches('/').rsplit('/').next().filter(|s| !s.is_empty())
}

pub fn is_entity_path(path: &str, prefixes: &[String]) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or("");
    prefixes.iter().any(|prefix| ENTITY_PREFIXES.iter().any(|p| path.starts_with(&format!("{prefix}{p}"))))
}

pub fn is_address_path(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or("");
    path.strip_prefix('/').is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

pub fn parse_address(name: &str, domain: &str) -> Option<(String, String)> {
    let name = name.to_lowercase();
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')) {
        return None;
    }
    let domain = domain.to_lowercase();
    if !domain.contains('.') || domain.ends_with(".local") || domain.ends_with(".internal") || domain.ends_with(".localhost") || domain.split('.').all(|l| l.parse::<u8>().is_ok()) {
        return None;
    }
    Some((name, domain))
}

async fn hint_allowed(url: &RelayUrl, allow_private: bool) -> bool {
    let Ok(url) = reqwest::Url::parse(url.as_str()) else { return false };
    if allow_private {
        return true;
    }
    match url.host_str() {
        Some(host) if url.scheme() == "wss" && url.port_or_known_default() == Some(443) => crate::health::resolves_public(host, 443).await == Some(true),
        _ => false,
    }
}

async fn fetch_hints(mirror: &Mirror, hints: Vec<RelayUrl>, filter: Filter, limits: &Arc<HintLimits>) {
    let mut tasks = tokio::task::JoinSet::new();
    for url in hints {
        if !limits.claim(&url) {
            continue;
        }
        let (database, filter, limits) = (mirror.database.clone(), filter.clone(), limits.clone());
        tasks.spawn(async move {
            let mut fetched = false;
            if hint_allowed(&url, limits.allow_private).await {
                let relay = nostr_sdk::relay::Relay::builder(url.clone()).database(database).build();
                fetched = tokio::time::timeout(FETCH_TIMEOUT, async { relay.try_connect().await.is_ok() && relay.fetch_events(vec![filter]).await.is_ok() }).await.unwrap_or(false);
                relay.disconnect();
            }
            limits.release(&url, !fetched);
        });
    }
    while tasks.join_next().await.is_some() {}
}

async fn lookup(mirror: &Mirror, filter: Value, key: &str, hints: Vec<RelayUrl>, limits: Option<&Arc<HintLimits>>) -> Vec<Event> {
    let found = mirror.query(std::slice::from_ref(&filter)).await;
    if !found.is_empty() || !mirror.should_try(key) {
        return found;
    }
    if let Some((f, _)) = parse_filter(&filter) {
        let hinted = async {
            if let Some(limits) = limits {
                fetch_hints(mirror, hints, f.clone(), limits).await;
            }
        };
        tokio::join!(mirror.fetch(vec![f.clone()], FETCH_TIMEOUT), hinted);
    }
    mirror.query(&[filter]).await
}

async fn profile(mirror: &Mirror, pubkey: &PublicKey) -> Option<Profile> {
    let ev = lookup(mirror, json!({"kinds": [0], "authors": [pubkey.to_hex()], "limit": 1}), &format!("og-profile:{pubkey}"), Vec::new(), None).await.into_iter().next()?;
    let v: Value = serde_json::from_str(&ev.content).ok()?;
    let text = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    Some(Profile { name: text("name"), about: text("about"), picture: text("picture") })
}

fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_string(), value.to_string())
}

pub fn profile_tags(og: &OpenGraph, pubkey: &PublicKey, profile: Option<&Profile>) -> Tags {
    let name = profile.and_then(|p| p.name.as_deref()).unwrap_or("Nostrich");
    let title = profile.map(|_| format!("{name}'s Profile")).unwrap_or_default();
    let description = profile.and_then(|p| p.about.as_deref()).map(|a| clip(a, 160)).unwrap_or_default();
    let image = profile.and_then(|p| p.picture.clone()).unwrap_or_else(|| avatar(og, pubkey));
    let json_ld = profile.map(|_| json!({"@context": "https://schema.org", "@type": "Person", "name": title, "description": description, "image": image}).to_string());
    Tags {
        metas: vec![
            pair("og:type", "profile"),
            pair("og:title", &title),
            pair("og:description", &description),
            pair("og:image", &image),
            pair("twitter:card", "summary"),
            pair("twitter:title", &title),
            pair("twitter:description", &description),
            pair("twitter:image", &image),
        ],
        title: Some(title).filter(|t| !t.is_empty()),
        canonical: None,
        json_ld,
        ..Default::default()
    }
}

fn live_tags(og: &OpenGraph, ev: &Event, host_profile: Option<&Profile>, host: &PublicKey, player: Option<&str>) -> Tags {
    let host_name = host_profile.and_then(|p| p.name.as_deref()).unwrap_or("Nostrich");
    let stream = tag_value(ev, "streaming").or_else(|| tag_value(ev, "recording")).unwrap_or("");
    let image = tag_value(ev, "image").map(str::to_string).or_else(|| host_profile.and_then(|p| p.picture.clone())).unwrap_or_else(|| avatar(og, host));
    let title = tag_value(ev, "title").unwrap_or("");
    let heading = format!("{host_name} is streaming");
    let mut metas = vec![
        pair("og:type", "video.other"),
        pair("og:title", &heading),
        pair("og:description", title),
        pair("og:image", &image),
        pair("og:video", stream),
        pair("og:video:secure_url", stream),
        pair("og:video:type", "application/vnd.apple.mpegurl"),
        pair("twitter:card", if player.is_some() { "player" } else { "summary_large_image" }),
        pair("twitter:title", &heading),
        pair("twitter:description", title),
        pair("twitter:image", &image),
    ];
    if let Some(site) = &og.twitter_site {
        metas.push(pair("twitter:site", site));
    }
    if let Some(player) = player {
        metas.push(pair("twitter:player", player));
        metas.push(pair("twitter:player:width", "640"));
        metas.push(pair("twitter:player:height", "480"));
        metas.push(pair("twitter:text:player_height", "480"));
    }
    let json_ld = json!({"@context": "https://schema.org", "@type": "BroadcastEvent", "name": title, "description": title, "streamURL": stream, "performer": {"@type": "Person", "name": host_name}}).to_string();
    Tags { metas, title: Some(heading), canonical: None, json_ld: Some(json_ld), ..Default::default() }
}

fn clip_tags(og: &OpenGraph, ev: &Event, author: Option<&Profile>) -> Tags {
    let name = author.and_then(|p| p.name.as_deref()).unwrap_or("Nostrich");
    let stream = tag_value(ev, "r").unwrap_or("");
    let image = tag_value(ev, "image").map(str::to_string).or_else(|| author.and_then(|p| p.picture.clone())).unwrap_or_else(|| avatar(og, &ev.pubkey));
    let title = tag_value(ev, "title").unwrap_or("");
    let heading = format!("{name} created a clip");
    let metas = vec![
        pair("og:type", "video.other"),
        pair("og:title", &heading),
        pair("og:description", title),
        pair("og:image", &image),
        pair("og:video", stream),
        pair("og:video:secure_url", stream),
        pair("og:video:type", "video/mp4"),
        pair("twitter:card", "summary_large_image"),
        pair("twitter:title", &heading),
        pair("twitter:description", title),
        pair("twitter:image", &image),
    ];
    let json_ld = json!({"@context": "https://schema.org", "@type": "Clip", "name": title, "description": title, "video": {"@type": "VideoObject", "contentURL": stream}, "actor": {"@type": "Person", "name": name}}).to_string();
    Tags { metas, title: Some(heading), canonical: None, json_ld: Some(json_ld), ..Default::default() }
}

fn iso_duration(secs: f64) -> String {
    let s = secs.round() as u64;
    match (s / 3600, s % 3600 / 60, s % 60) {
        (0, m, s) => format!("PT{m}M{s}S"),
        (h, m, s) => format!("PT{h}H{m}M{s}S"),
    }
}

fn video_tags(og: &OpenGraph, ev: &Event, media: &Media, author: Option<&Profile>, player: Option<&str>) -> Tags {
    let primary = media.metas.iter().find(|m| m.get("url") == Some(&media.url));
    let mime = primary.and_then(|m| m.get("m"));
    let dim = primary.and_then(|m| m.get("dim")).and_then(|d| d.split_once('x'));
    let title = if media.title.is_empty() { clip(&ev.content, 160) } else { media.title.clone() };
    let description = clip(tag_value(ev, "summary").unwrap_or(&ev.content), 200);
    let image = media.thumbnail.clone().or_else(|| author.and_then(|p| p.picture.clone())).unwrap_or_else(|| avatar(og, &ev.pubkey));
    let mut metas = vec![
        pair("og:type", "video.other"),
        pair("og:title", &title),
        pair("og:description", &description),
        pair("og:image", &image),
        pair("og:video", &media.url),
        pair("og:video:secure_url", &media.url),
    ];
    if let Some(m) = mime {
        metas.push(pair("og:video:type", m));
    }
    if let Some((w, h)) = dim {
        metas.push(pair("og:video:width", w));
        metas.push(pair("og:video:height", h));
    }
    metas.extend([
        pair("twitter:card", if player.is_some() { "player" } else { "summary_large_image" }),
        pair("twitter:title", &title),
        pair("twitter:description", &description),
        pair("twitter:image", &image),
    ]);
    if let Some(site) = &og.twitter_site {
        metas.push(pair("twitter:site", site));
    }
    if let Some(player) = player {
        let (w, h) = dim.unwrap_or(("640", "360"));
        metas.push(pair("twitter:player", player));
        metas.push(pair("twitter:player:width", w));
        metas.push(pair("twitter:player:height", h));
    }
    let mut ld = json!({"@context": "https://schema.org", "@type": "VideoObject", "name": title, "description": description, "thumbnailUrl": image, "uploadDate": crate::sitemap::iso(ev.created_at.as_secs() as i64), "contentUrl": media.url});
    if let Some(d) = media.duration {
        ld["duration"] = json!(iso_duration(d));
    }
    if let Some(p) = player {
        ld["embedUrl"] = json!(p);
    }
    if let Some(name) = author.and_then(|p| p.name.as_deref()) {
        ld["author"] = json!({"@type": "Person", "name": name});
    }
    Tags { metas, title: Some(title), canonical: None, json_ld: Some(ld.to_string()), ..Default::default() }
}

fn picture_tags(og: &OpenGraph, ev: &Event, media: &Media, author: Option<&Profile>) -> Tags {
    let mut tags = post_tags(og, ev, author);
    for (key, value) in tags.metas.iter_mut() {
        match key.as_str() {
            "og:image" | "twitter:image" => *value = media.url.clone(),
            "twitter:card" => *value = "summary_large_image".into(),
            _ => {}
        }
    }
    tags
}

fn post_tags(og: &OpenGraph, ev: &Event, author: Option<&Profile>) -> Tags {
    let name = author.and_then(|p| p.name.as_deref()).unwrap_or("Nostrich");
    let heading = tag_value(ev, "title").filter(|t| !t.is_empty()).map(str::to_string).unwrap_or_else(|| format!("{name}: {}", clip(&ev.content, 160)));
    let description = tag_value(ev, "summary").map(|s| clip(s, 200)).unwrap_or_default();
    let image = author.and_then(|p| p.picture.clone()).unwrap_or_else(|| avatar(og, &ev.pubkey));
    let profile_name = author.and_then(|p| p.name.as_deref()).unwrap_or("");
    let published = crate::sitemap::iso(ev.created_at.as_secs() as i64);
    let metas = vec![
        pair("og:type", "article"),
        pair("og:title", &heading),
        pair("og:description", &description),
        pair("og:image", &image),
        pair("og:article:published_time", &published),
        pair("og:article:author:username", profile_name),
        pair("twitter:card", "summary"),
        pair("twitter:title", &heading),
        pair("twitter:description", &description),
        pair("twitter:image", &image),
    ];
    let json_ld = json!({"@context": "https://schema.org", "@type": "Comment", "name": profile_name, "description": ev.content.replace('\n', " "), "datePublished": published, "author": {"@type": "Person", "name": profile_name}}).to_string();
    Tags { metas, title: Some(heading), canonical: None, json_ld: Some(json_ld), ..Default::default() }
}

fn player_url(template: &str, ev: &Event, nip19: &str, requested: Option<&str>, origin: &str) -> String {
    let nevent = Nip19Event::new(ev.id).author(ev.pubkey).kind(ev.kind).to_bech32().unwrap_or_default();
    absolute(origin, &template.replace("{nevent}", &nevent).replace("{nip19}", nip19).replace("{id}", requested.unwrap_or(nip19)))
}

fn nip19(ev: &Event) -> Option<String> {
    match ev.coordinate() {
        Some(c) => Nip19Coordinate::new(c, Vec::<RelayUrl>::new()).to_bech32().ok(),
        None => Nip19Event::from(ev).to_bech32().ok(),
    }
}

fn stream_host(ev: &Event) -> PublicKey {
    ev.tags
        .iter()
        .find(|t| {
            let s = t.as_slice();
            s.first().map(String::as_str) == Some("p") && s.len() > 3 && s[3].eq_ignore_ascii_case("host")
        })
        .and_then(|t| t.as_slice().get(1).and_then(|h| PublicKey::from_hex(h).ok()))
        .unwrap_or(ev.pubkey)
}

pub async fn event_tags(og: &OpenGraph, mirror: &Mirror, ev: &Event, origin: &str, requested: Option<&str>) -> Tags {
    let link = og.links.iter().find(|l| l.kinds.contains(&ev.kind.as_u16()));
    let entity = nip19(ev);
    let player = link.and_then(|l| l.player.as_deref()).or(og.player.as_deref()).map(|t| player_url(t, ev, entity.as_deref().unwrap_or(""), requested, origin));
    let author = if ev.kind.as_u16() == 30311 { stream_host(ev) } else { ev.pubkey };
    let mut tags = match ev.kind.as_u16() {
        30311 => {
            let p = profile(mirror, &author).await;
            live_tags(og, ev, p.as_ref(), &author, player.as_deref())
        }
        IMAGE_KIND | VIDEO_KIND | SHORTS_KIND | OLD_VIDEO_KIND | OLD_SHORTS_KIND => {
            let p = profile(mirror, &ev.pubkey).await;
            match crate::media::parse(ev) {
                Some(media) if media.is_image() => picture_tags(og, ev, &media, p.as_ref()),
                Some(media) => video_tags(og, ev, &media, p.as_ref(), player.as_deref()),
                None => post_tags(og, ev, p.as_ref()),
            }
        }
        1313 => {
            let p = profile(mirror, &ev.pubkey).await;
            clip_tags(og, ev, p.as_ref())
        }
        _ => {
            let p = profile(mirror, &ev.pubkey).await;
            post_tags(og, ev, p.as_ref())
        }
    };
    let path = link.map(|l| l.path.as_str()).unwrap_or("/{nip19}");
    tags.canonical = entity.map(|l| format!("{}{}", origin.trim_end_matches('/'), path.replace("{nip19}", &l)));
    tags.author = Some(author);
    tags
}

impl State {
    async fn resolve_address(&self, og: &OpenGraph, name: &str, domain: &str, host: &str) -> Option<PublicKey> {
        let (name, domain) = parse_address(name, domain)?;
        let key = format!("{name}@{domain}");
        if let Some((at, found)) = self.nip05.lock().unwrap().get(&key) {
            if at.elapsed() < if found.is_some() { NIP05_TTL } else { NIP05_NEGATIVE_TTL } {
                return *found;
            }
        }
        let url = match &og.nip05_url {
            Some(t) => t.replace("{name}", &name),
            None => format!("https://{domain}/.well-known/nostr.json?name={name}"),
        };
        let mut req = self.client.get(url).timeout(NIP05_TIMEOUT);
        for (k, v) in &og.nip05_headers {
            req = req.header(k.as_str(), v.replace("{host}", host));
        }
        let found = async {
            let body: Value = req.send().await.ok()?.error_for_status().ok()?.json().await.ok()?;
            PublicKey::from_hex(body.get("names")?.get(&name)?.as_str()?).ok()
        }
        .await;
        self.nip05.lock().unwrap().insert(key, (Instant::now(), found));
        found
    }
}

pub async fn tags_for(state: &State, config: &Config, mirror: &Mirror, path: &str, origin: &str) -> Option<Tags> {
    let og = config.opengraph.as_ref()?;
    let id = last_segment(path)?;
    let bare = path.split(['?', '#']).next().unwrap_or("");
    let entity = is_entity_path(path, &og.entity_prefixes);
    let address = og.addresses && !entity && is_address_path(path) && !og.skip_paths.iter().chain(config.static_paths.iter()).any(|p| p == bare);
    if !entity && !address {
        return None;
    }
    let target = if address {
        let host = origin.split("://").nth(1).unwrap_or(origin).split(':').next().unwrap_or("");
        let domain = og.nip05_domain.clone().unwrap_or_else(|| host.to_string());
        Nip19::Pubkey(state.resolve_address(og, id, &domain, host).await?)
    } else {
        Nip19::from_bech32(id).ok()?
    };
    let mut tags = match target {
        Nip19::Pubkey(pk) => Tags { author: Some(pk), ..profile_tags(og, &pk, profile(mirror, &pk).await.as_ref()) },
        Nip19::Profile(p) => Tags { author: Some(p.public_key), ..profile_tags(og, &p.public_key, profile(mirror, &p.public_key).await.as_ref()) },
        Nip19::EventId(_) | Nip19::Event(_) | Nip19::Coordinate(_) => {
            let (filter, key, hints) = match &target {
                Nip19::EventId(i) => (json!({"ids": [i.to_hex()]}), i.to_hex(), Vec::new()),
                Nip19::Event(e) => (json!({"ids": [e.event_id.to_hex()]}), e.event_id.to_hex(), e.relays.clone()),
                Nip19::Coordinate(c) => (json!({"kinds": [c.kind.as_u16()], "authors": [c.public_key.to_hex()], "#d": [c.identifier]}), format!("{}:{}:{}", c.kind.as_u16(), c.public_key, c.identifier), c.relays.clone()),
                _ => return None,
            };
            let hints = hints.into_iter().take(og.hint_relays).collect();
            let ev = lookup(mirror, filter, &format!("og-event:{key}"), hints, Some(&state.hints)).await.into_iter().next()?;
            event_tags(og, mirror, &ev, origin, Some(id)).await
        }
        _ => return None,
    };
    let canonical = tags.canonical.get_or_insert_with(|| format!("{}{bare}", origin.trim_end_matches('/'))).clone();
    tags.metas.push(pair("og:url", &canonical));
    if let Some(o) = &config.oembed {
        tags.oembed = Some(format!("{}{}?url={}&format=json", origin.trim_end_matches('/'), o.path, crate::media::url_encode(&canonical)));
    }
    Some(tags)
}

pub async fn oembed(state: &State, config: &Config, mirror: &Mirror, url: &str, origin: &str) -> Option<Value> {
    let settings = config.oembed.as_ref()?;
    let path = url.strip_prefix(origin.trim_end_matches('/')).filter(|p| p.starts_with('/'))?;
    let tags = tags_for(state, config, mirror, path, origin).await?;
    let meta = |key: &str| tags.metas.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    let mut doc = json!({"version": "1.0", "type": "link", "title": meta("og:title").unwrap_or(""), "provider_name": config.site_name, "provider_url": origin, "cache_age": 600});
    if let Some(image) = meta("og:image") {
        doc["thumbnail_url"] = json!(image);
    }
    if let Some(pk) = tags.author {
        doc["author_url"] = json!(format!("{}{}", origin.trim_end_matches('/'), crate::media::profile_path(&pk)));
        if let Some(name) = profile(mirror, &pk).await.and_then(|p| p.name) {
            doc["author_name"] = json!(name);
        }
    }
    if let Some(player) = meta("twitter:player") {
        let (w, h) = (settings.width, settings.height);
        doc["type"] = json!("video");
        doc["html"] = json!(format!("<iframe src=\"{}\" width=\"{w}\" height=\"{h}\" frameborder=\"0\" allowfullscreen allow=\"autoplay; fullscreen\"></iframe>", escape_html(player)));
        doc["width"] = json!(w);
        doc["height"] = json!(h);
    }
    Some(doc)
}

fn strip(head: &str, pattern: &str) -> String {
    Regex::new(pattern).map(|re| re.replace_all(head, "").into_owned()).unwrap_or_else(|_| head.to_string())
}

pub fn merge(head: &str, tags: &Tags) -> String {
    let mut out = head.to_string();
    for (key, _) in &tags.metas {
        out = strip(&out, &format!(r#"<meta\s[^>]*?(?:property|name)="{}"[^>]*?/?>"#, regex::escape(key)));
    }
    if tags.title.is_some() {
        out = strip(&out, r"<title[^>]*>[^<]*</title>");
    }
    if tags.canonical.is_some() {
        out = strip(&out, r#"<link\s[^>]*?rel="canonical"[^>]*?/?>"#);
    }
    if tags.json_ld.is_some() {
        out = strip(&out, r#"(?s)<script\s[^>]*?type="application/ld\+json"[^>]*>.*?</script>"#);
    }
    let mut added = Vec::new();
    for (key, value) in &tags.metas {
        added.push(format!("<meta property=\"{}\" content=\"{}\" />", escape_html(key), escape_html(value)));
    }
    if let Some(t) = &tags.title {
        added.push(format!("<title>{}</title>", escape_html(t)));
    }
    if let Some(c) = &tags.canonical {
        added.push(format!("<link rel=\"canonical\" href=\"{}\" />", escape_html(c)));
    }
    if let Some(href) = &tags.oembed {
        added.push(format!("<link rel=\"alternate\" type=\"application/json+oembed\" href=\"{}\" />", escape_html(href)));
    }
    if let Some(ld) = &tags.json_ld {
        added.push(format!("<script type=\"application/ld+json\">{}</script>", ld.replace("</", "<\\/")));
    }
    format!("{}\n    {}", out.trim_end(), added.join("\n    "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::FinalizeEvent;
    use nostr_database::NostrDatabase;

    fn keys(n: u8) -> Keys {
        Keys::new(SecretKey::from_slice(&[n; 32]).unwrap())
    }

    fn og() -> OpenGraph {
        OpenGraph { twitter_site: Some("@zap_stream".into()), player: Some("https://zap.stream/embed/{nevent}".into()), ..OpenGraph::default() }
    }

    async fn save(m: &Mirror, ev: &Event) {
        m.database.save_event(ev).await.unwrap();
    }

    fn profile_event(n: u8, json: &str) -> Event {
        EventBuilder::new(Kind::Metadata, json).finalize(&keys(n)).unwrap()
    }

    fn event(n: u8, kind: u16, content: &str, tags: Vec<Vec<&str>>) -> Event {
        EventBuilder::new(Kind::from(kind), content).tags(tags.into_iter().map(|t| Tag::parse(t).unwrap())).custom_created_at(Timestamp::from_secs(1_700_000_000)).finalize(&keys(n)).unwrap()
    }

    fn meta<'a>(t: &'a Tags, key: &str) -> Option<&'a str> {
        t.metas.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[tokio::test]
    async fn a_live_stream_is_tagged_as_a_playable_video_with_the_host_name_stream_url_and_player() {
        let m = Mirror::new(0, None, &[]);
        let host = keys(2);
        save(&m, &profile_event(2, r#"{"name":"alice","picture":"https://x/a.png"}"#)).await;
        let ev = event(1, 30311, "", vec![vec!["d", "room"], vec!["title", "Late show"], vec!["streaming", "https://cdn/live.m3u8"], vec!["image", "https://x/cover.png"], vec!["p", &host.public_key().to_hex(), "", "Host"]]);
        let t = event_tags(&og(), &m, &ev, "https://zap.stream", None).await;
        assert_eq!(meta(&t, "og:type"), Some("video.other"));
        assert_eq!(meta(&t, "og:title"), Some("alice is streaming"));
        assert_eq!(meta(&t, "og:description"), Some("Late show"));
        assert_eq!(meta(&t, "og:image"), Some("https://x/cover.png"));
        assert_eq!(meta(&t, "og:video"), Some("https://cdn/live.m3u8"));
        assert_eq!(meta(&t, "og:video:secure_url"), Some("https://cdn/live.m3u8"));
        assert_eq!(meta(&t, "og:video:type"), Some("application/vnd.apple.mpegurl"));
        assert_eq!(meta(&t, "twitter:card"), Some("player"));
        assert_eq!(meta(&t, "twitter:site"), Some("@zap_stream"));
        assert!(meta(&t, "twitter:player").unwrap().starts_with("https://zap.stream/embed/nevent1"));
        assert_eq!(meta(&t, "twitter:player:width"), Some("640"));
        assert!(t.json_ld.as_deref().unwrap().contains("\"BroadcastEvent\""));
        assert!(t.canonical.as_deref().unwrap().starts_with("https://zap.stream/naddr1"));
    }

    #[tokio::test]
    async fn an_ended_stream_falls_back_to_the_recording_and_the_host_avatar_when_there_is_no_image() {
        let m = Mirror::new(0, None, &[]);
        let ev = event(1, 30311, "", vec![vec!["d", "room"], vec!["recording", "https://cdn/rec.m3u8"]]);
        let t = event_tags(&og(), &m, &ev, "https://zap.stream", None).await;
        assert_eq!(meta(&t, "og:video"), Some("https://cdn/rec.m3u8"));
        assert_eq!(meta(&t, "og:title"), Some("Nostrich is streaming"));
        assert!(meta(&t, "og:image").unwrap().contains(&keys(1).public_key().to_hex()));
    }

    #[tokio::test]
    async fn a_stream_clip_is_tagged_as_an_mp4_video_from_its_r_tag() {
        let m = Mirror::new(0, None, &[]);
        save(&m, &profile_event(1, r#"{"name":"bob"}"#)).await;
        let ev = event(1, 1313, "", vec![vec!["r", "https://cdn/clip.mp4"], vec!["title", "Big moment"]]);
        let t = event_tags(&og(), &m, &ev, "https://zap.stream", None).await;
        assert_eq!(meta(&t, "og:title"), Some("bob created a clip"));
        assert_eq!(meta(&t, "og:video"), Some("https://cdn/clip.mp4"));
        assert_eq!(meta(&t, "og:video:type"), Some("video/mp4"));
        assert_eq!(meta(&t, "twitter:card"), Some("summary_large_image"));
        assert!(t.json_ld.as_deref().unwrap().contains("\"Clip\""));
        assert!(t.canonical.as_deref().unwrap().starts_with("https://zap.stream/nevent1"));
    }

    fn player_og() -> OpenGraph {
        OpenGraph { player: Some("/embed?v={nip19}".into()), ..OpenGraph::default() }
    }

    #[tokio::test]
    async fn a_video_is_tagged_with_its_mp4_size_thumbnail_and_player() {
        let m = Mirror::new(0, None, &[]);
        let ev = event(1, 21, "about the trip", vec![vec!["title", "Trip"], vec!["imeta", "url https://cdn/v.mp4", "m video/mp4", "dim 1280x720", "image https://cdn/v.jpg"]]);
        let t = event_tags(&player_og(), &m, &ev, "https://example.com", None).await;
        assert_eq!(meta(&t, "og:type"), Some("video.other"));
        assert_eq!(meta(&t, "og:title"), Some("Trip"));
        assert_eq!(meta(&t, "og:description"), Some("about the trip"));
        assert_eq!(meta(&t, "og:image"), Some("https://cdn/v.jpg"));
        assert_eq!(meta(&t, "og:video"), Some("https://cdn/v.mp4"));
        assert_eq!(meta(&t, "og:video:type"), Some("video/mp4"));
        assert_eq!((meta(&t, "og:video:width"), meta(&t, "og:video:height")), (Some("1280"), Some("720")));
        assert_eq!(meta(&t, "twitter:card"), Some("player"));
        assert!(meta(&t, "twitter:player").unwrap().starts_with("https://example.com/embed?v=nevent1"));
        assert_eq!((meta(&t, "twitter:player:width"), meta(&t, "twitter:player:height")), (Some("1280"), Some("720")));
        assert_eq!(t.title.as_deref(), Some("Trip"));
    }

    #[tokio::test]
    async fn an_hls_only_video_is_tagged_as_a_playlist() {
        let m = Mirror::new(0, None, &[]);
        let ev = event(1, 22, "", vec![vec!["title", "Short"], vec!["imeta", "url https://cdn/v.m3u8", "m application/x-mpegURL"]]);
        let t = event_tags(&player_og(), &m, &ev, "https://example.com", None).await;
        assert_eq!(meta(&t, "og:video"), Some("https://cdn/v.m3u8"));
        assert_eq!(meta(&t, "og:video:type"), Some("application/x-mpegURL"));
        assert_eq!((meta(&t, "twitter:player:width"), meta(&t, "twitter:player:height")), (Some("640"), Some("360")));
    }

    #[tokio::test]
    async fn video_json_ld_has_an_iso_duration_and_upload_date() {
        let m = Mirror::new(0, None, &[]);
        let ev = event(1, 21, "", vec![vec!["title", "Long"], vec!["summary", "A long one"], vec!["imeta", "url https://cdn/v.mp4", "m video/mp4", "duration 3754.4"]]);
        let t = event_tags(&player_og(), &m, &ev, "https://example.com", None).await;
        let ld: Value = serde_json::from_str(t.json_ld.as_deref().unwrap()).unwrap();
        assert_eq!(ld["@type"], "VideoObject");
        assert_eq!(ld["description"], "A long one");
        assert_eq!(ld["duration"], "PT1H2M34S");
        assert!(ld["uploadDate"].as_str().unwrap().starts_with("2023-11-14T"));
        assert_eq!(ld["contentUrl"], "https://cdn/v.mp4");
        assert!(ld["embedUrl"].as_str().unwrap().starts_with("https://example.com/embed?v="));
    }

    #[tokio::test]
    async fn an_event_with_a_title_tag_uses_it_over_its_content() {
        let m = Mirror::new(0, None, &[]);
        let ev = event(1, 30005, "", vec![vec!["d", "list"], vec!["title", "My list"], vec!["summary", "Best clips"]]);
        let t = event_tags(&OpenGraph::default(), &m, &ev, "https://example.com", None).await;
        assert_eq!(meta(&t, "og:title"), Some("My list"));
        assert_eq!(meta(&t, "og:description"), Some("Best clips"));
        assert_eq!(t.title.as_deref(), Some("My list"));
    }

    #[tokio::test]
    async fn a_picture_post_is_tagged_with_its_picture() {
        let m = Mirror::new(0, None, &[]);
        let ev = event(1, 20, "sunset", vec![vec!["imeta", "url https://cdn/p.jpg", "m image/jpeg"]]);
        let t = event_tags(&OpenGraph::default(), &m, &ev, "https://example.com", None).await;
        assert_eq!(meta(&t, "og:image"), Some("https://cdn/p.jpg"));
        assert_eq!(meta(&t, "twitter:image"), Some("https://cdn/p.jpg"));
        assert_eq!(meta(&t, "twitter:card"), Some("summary_large_image"));
    }

    fn oembed_config(og: OpenGraph) -> Config {
        Config { site_name: "Demo".into(), opengraph: Some(og), oembed: Some(crate::config::Oembed::default()), ..Config::default() }
    }

    #[tokio::test]
    async fn oembed_returns_a_video_iframe_for_a_page_with_a_player() {
        let m = Mirror::new(0, None, &[]);
        save(&m, &profile_event(1, r#"{"name":"erin"}"#)).await;
        let ev = event(1, 21, "", vec![vec!["title", "Trip"], vec!["imeta", "url https://cdn/v.mp4", "m video/mp4", "dim 1920x1080", "image https://cdn/v.jpg"]]);
        save(&m, &ev).await;
        let nevent = Nip19Event::from(&ev).to_bech32().unwrap();
        let doc = oembed(&State::default(), &oembed_config(player_og()), &m, &format!("https://example.com/{nevent}"), "https://example.com").await.unwrap();
        assert_eq!(doc["type"], "video");
        assert_eq!(doc["title"], "Trip");
        assert_eq!(doc["author_name"], "erin");
        assert!(doc["author_url"].as_str().unwrap().starts_with("https://example.com/p/nprofile1"));
        assert_eq!(doc["thumbnail_url"], "https://cdn/v.jpg");
        assert_eq!(doc["provider_name"], "Demo");
        assert_eq!((doc["width"].as_u64(), doc["height"].as_u64()), (Some(640), Some(360)));
        assert!(doc["html"].as_str().unwrap().starts_with(&format!("<iframe src=\"https://example.com/embed?v={nevent}\" width=\"640\" height=\"360\"")));
    }

    #[tokio::test]
    async fn oembed_returns_a_link_for_tagged_pages_without_a_player() {
        let m = Mirror::new(0, None, &[]);
        save(&m, &profile_event(3, r#"{"name":"dave"}"#)).await;
        let npub = keys(3).public_key().to_bech32().unwrap();
        let doc = oembed(&State::default(), &oembed_config(player_og()), &m, &format!("https://example.com/{npub}"), "https://example.com").await.unwrap();
        assert_eq!(doc["type"], "link");
        assert_eq!(doc["title"], "dave's Profile");
        assert!(doc.get("html").is_none());
    }

    #[tokio::test]
    async fn tagged_pages_link_their_oembed_document() {
        let m = Mirror::new(0, None, &[]);
        save(&m, &profile_event(3, r#"{"name":"dave"}"#)).await;
        let npub = keys(3).public_key().to_bech32().unwrap();
        let t = tags_for(&State::default(), &oembed_config(player_og()), &m, &format!("/{npub}"), "https://example.com").await.unwrap();
        let href = format!("https://example.com/oembed?url=https%3A%2F%2Fexample.com%2F{npub}&format=json");
        assert_eq!(t.oembed.as_deref(), Some(href.as_str()));
        assert!(merge("", &t).contains(&format!("<link rel=\"alternate\" type=\"application/json+oembed\" href=\"{}\" />", escape_html(&href))));
        assert!(tags_for(&State::default(), &Config { oembed: None, ..oembed_config(player_og()) }, &m, &format!("/{npub}"), "https://example.com").await.unwrap().oembed.is_none());
    }

    #[tokio::test]
    async fn oembed_rejects_foreign_and_untagged_urls() {
        let m = Mirror::new(0, None, &[]);
        save(&m, &profile_event(3, r#"{"name":"dave"}"#)).await;
        let npub = keys(3).public_key().to_bech32().unwrap();
        let config = oembed_config(player_og());
        assert!(oembed(&State::default(), &config, &m, &format!("https://other.example/{npub}"), "https://example.com").await.is_none());
        assert!(oembed(&State::default(), &config, &m, &format!("https://example.com.other.example/{npub}"), "https://example.com").await.is_none());
        assert!(oembed(&State::default(), &config, &m, "https://example.com/streams", "https://example.com").await.is_none());
        assert!(oembed(&State::default(), &Config { oembed: None, ..config }, &m, &format!("https://example.com/{npub}"), "https://example.com").await.is_none());
    }

    #[tokio::test]
    async fn a_video_without_a_player_gets_a_large_image_card() {
        let m = Mirror::new(0, None, &[]);
        let ev = event(1, 21, "", vec![vec!["title", "Trip"], vec!["imeta", "url https://cdn/v.mp4", "m video/mp4"]]);
        let t = event_tags(&OpenGraph::default(), &m, &ev, "https://example.com", None).await;
        assert_eq!(meta(&t, "twitter:card"), Some("summary_large_image"));
        assert_eq!(meta(&t, "twitter:player"), None);
        assert_eq!(meta(&t, "og:video"), Some("https://cdn/v.mp4"));
    }

    #[tokio::test]
    async fn other_kinds_are_tagged_as_articles_with_the_author_and_trimmed_content() {
        let m = Mirror::new(0, None, &[]);
        save(&m, &profile_event(1, r#"{"name":"carol","picture":"https://x/c.png"}"#)).await;
        let ev = event(1, 1, &"x".repeat(300), vec![]);
        let t = event_tags(&og(), &m, &ev, "https://zap.stream", None).await;
        assert_eq!(meta(&t, "og:type"), Some("article"));
        assert_eq!(meta(&t, "og:title").unwrap().chars().count(), "carol: ".len() + 160);
        assert_eq!(meta(&t, "og:image"), Some("https://x/c.png"));
        assert_eq!(meta(&t, "og:article:author:username"), Some("carol"));
        assert!(meta(&t, "og:article:published_time").unwrap().starts_with("2023-11-14T"));
    }

    #[tokio::test]
    async fn a_kind_link_sets_the_canonical_path() {
        let m = Mirror::new(0, None, &[]);
        let o = OpenGraph { links: vec![crate::config::Link { kinds: vec![30311], path: "/live/{nip19}".into(), player: None }], ..og() };
        let live = event(1, 30311, "", vec![vec!["d", "room"]]);
        assert!(event_tags(&o, &m, &live, "https://example.com", None).await.canonical.unwrap().starts_with("https://example.com/live/naddr1"));
        let note = event(1, 1, "hi", vec![]);
        assert!(event_tags(&o, &m, &note, "https://example.com", None).await.canonical.unwrap().starts_with("https://example.com/nevent1"));
    }

    #[tokio::test]
    async fn a_stream_without_a_player_gets_a_large_image_card() {
        let m = Mirror::new(0, None, &[]);
        let o = OpenGraph { player: None, ..og() };
        let live = event(1, 30311, "", vec![vec!["d", "room"], vec!["streaming", "https://cdn/l.m3u8"]]);
        let t = event_tags(&o, &m, &live, "https://example.com", None).await;
        assert_eq!(meta(&t, "twitter:card"), Some("summary_large_image"));
        assert_eq!(meta(&t, "twitter:player"), None);
    }

    #[tokio::test]
    async fn a_link_player_overrides_the_site_player() {
        let m = Mirror::new(0, None, &[]);
        let o = OpenGraph { links: vec![crate::config::Link { kinds: vec![30311], path: "/live/{nip19}".into(), player: Some("https://example.com/watch/{nip19}".into()) }], ..og() };
        let live = event(1, 30311, "", vec![vec!["d", "room"]]);
        let t = event_tags(&o, &m, &live, "https://example.com", None).await;
        assert!(meta(&t, "twitter:player").unwrap().starts_with("https://example.com/watch/naddr1"));
    }

    #[tokio::test]
    async fn a_relative_player_becomes_absolute() {
        let m = Mirror::new(0, None, &[]);
        let o = OpenGraph { player: Some("/embed?e={nevent}".into()), ..og() };
        let live = event(1, 30311, "", vec![vec!["d", "room"]]);
        let t = event_tags(&o, &m, &live, "https://example.com", None).await;
        assert!(meta(&t, "twitter:player").unwrap().starts_with("https://example.com/embed?e=nevent1"));
    }

    #[tokio::test]
    async fn the_id_placeholder_keeps_the_requested_identifier() {
        let m = Mirror::new(0, None, &[]);
        let live = event(1, 30311, "", vec![vec!["d", "room"]]);
        save(&m, &live).await;
        let state = State::default();
        let config = Config { opengraph: Some(OpenGraph { player: Some("/embed?v={id}".into()), ..og() }), ..Config::default() };
        let hinted = Nip19Event::new(live.id).relays([RelayUrl::parse("wss://relay.example.com").unwrap()]).to_bech32().unwrap();
        let t = tags_for(&state, &config, &m, &format!("/e/{hinted}"), "https://example.com").await.unwrap();
        assert_eq!(meta(&t, "twitter:player"), Some(format!("https://example.com/embed?v={hinted}").as_str()));
    }

    #[tokio::test]
    async fn a_profile_link_is_tagged_with_the_profile_name_about_and_picture() {
        let m = Mirror::new(0, None, &[]);
        let pk = keys(3).public_key();
        save(&m, &profile_event(3, r#"{"name":"dave","about":"hello there","picture":"https://x/d.png"}"#)).await;
        let state = State::default();
        let config = Config { opengraph: Some(og()), ..Config::default() };
        let t = tags_for(&state, &config, &m, &format!("/{}", pk.to_bech32().unwrap()), "https://zap.stream").await.unwrap();
        assert_eq!(meta(&t, "og:type"), Some("profile"));
        assert_eq!(meta(&t, "og:title"), Some("dave's Profile"));
        assert_eq!(meta(&t, "og:description"), Some("hello there"));
        assert_eq!(meta(&t, "og:image"), Some("https://x/d.png"));
        assert!(t.json_ld.as_deref().unwrap().contains("\"Person\""));
    }

    #[tokio::test]
    async fn tagged_pages_set_og_url_to_their_canonical_link() {
        let m = Mirror::new(0, None, &[]);
        let live = event(1, 30311, "", vec![vec!["d", "room"], vec!["streaming", "https://cdn/l.m3u8"]]);
        save(&m, &live).await;
        let state = State::default();
        let config = Config { opengraph: Some(og()), ..Config::default() };
        let naddr = Nip19Coordinate::new(live.coordinate().unwrap(), Vec::<RelayUrl>::new()).to_bech32().unwrap();
        let t = tags_for(&state, &config, &m, &format!("/{naddr}"), "https://example.com").await.unwrap();
        assert_eq!(meta(&t, "og:url"), t.canonical.as_deref());
        let npub = keys(3).public_key().to_bech32().unwrap();
        let t = tags_for(&state, &config, &m, &format!("/p/{npub}?tab=notes"), "https://example.com").await.unwrap();
        assert_eq!(t.canonical, Some(format!("https://example.com/p/{npub}")));
        assert_eq!(meta(&t, "og:url"), t.canonical.as_deref());
    }

    #[tokio::test]
    async fn event_links_look_the_event_up_in_the_mirror_by_id_and_by_coordinate() {
        let m = Mirror::new(0, None, &[]);
        let live = event(1, 30311, "", vec![vec!["d", "room"], vec!["title", "T"], vec!["streaming", "https://cdn/l.m3u8"]]);
        save(&m, &live).await;
        let state = State::default();
        let config = Config { opengraph: Some(og()), ..Config::default() };
        let naddr = Nip19Coordinate::new(live.coordinate().unwrap(), Vec::<RelayUrl>::new()).to_bech32().unwrap();
        let t = tags_for(&state, &config, &m, &format!("/{naddr}"), "https://zap.stream").await.unwrap();
        assert_eq!(meta(&t, "og:video"), Some("https://cdn/l.m3u8"));
        let note = Nip19Event::new(live.id).to_bech32().unwrap();
        let t = tags_for(&state, &config, &m, &format!("/e/{note}"), "https://zap.stream").await.unwrap();
        assert_eq!(meta(&t, "og:video"), Some("https://cdn/l.m3u8"));
    }

    async fn hinted_live_event() -> (nostr_relay_builder::MockRelay, String) {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let live = event(1, 30311, "", vec![vec!["d", "room"], vec!["streaming", "https://cdn/l.m3u8"]]);
        relay.add_event(live.clone()).await.unwrap();
        let naddr = Nip19Coordinate::new(live.coordinate().unwrap(), [relay.url().await]).to_bech32().unwrap();
        (relay, format!("/{naddr}"))
    }

    fn hint_config(hint_relays: usize) -> Config {
        Config { opengraph: Some(OpenGraph { hint_relays, ..og() }), ..Config::default() }
    }

    #[tokio::test]
    async fn an_event_only_on_a_hinted_relay_is_found_when_hints_are_on() {
        let (_relay, path) = hinted_live_event().await;
        let state = State { hints: Arc::new(HintLimits { allow_private: true, ..HintLimits::default() }), ..State::default() };
        let t = tags_for(&state, &hint_config(3), &Mirror::new(0, None, &[]), &path, "https://example.com").await.unwrap();
        assert_eq!(meta(&t, "og:video"), Some("https://cdn/l.m3u8"));
    }

    #[tokio::test]
    async fn hints_are_ignored_by_default() {
        let (_relay, path) = hinted_live_event().await;
        let state = State { hints: Arc::new(HintLimits { allow_private: true, ..HintLimits::default() }), ..State::default() };
        assert!(tags_for(&state, &hint_config(0), &Mirror::new(0, None, &[]), &path, "https://example.com").await.is_none());
    }

    #[tokio::test]
    async fn private_and_plain_ws_hints_are_skipped() {
        let (_relay, path) = hinted_live_event().await;
        assert!(tags_for(&State::default(), &hint_config(3), &Mirror::new(0, None, &[]), &path, "https://example.com").await.is_none());
    }

    #[tokio::test]
    async fn only_public_wss_hints_are_allowed() {
        let url = |s: &str| RelayUrl::parse(s).unwrap();
        assert!(!hint_allowed(&url("ws://1.1.1.1"), false).await);
        assert!(!hint_allowed(&url("wss://127.0.0.1"), false).await);
        assert!(!hint_allowed(&url("wss://10.1.2.3:7777"), false).await);
        assert!(!hint_allowed(&url("wss://1.1.1.1:8443"), false).await);
        assert!(hint_allowed(&url("wss://1.1.1.1"), false).await);
    }

    #[test]
    fn a_hint_host_is_tried_once_per_interval_and_paused_after_a_failure() {
        let limits = HintLimits::default();
        let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
        assert!(limits.claim(&relay));
        assert!(!limits.claim(&relay));
        assert!(limits.claim(&RelayUrl::parse("wss://other.example.com").unwrap()));
        limits.release(&relay, true);
        assert!(limits.hosts.lock().unwrap()["relay.example.com"] > Instant::now() + HINT_HOST_INTERVAL);
        assert_eq!(limits.in_flight.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn hints_beyond_the_concurrency_limit_are_skipped() {
        let (_relay, path) = hinted_live_event().await;
        let state = State { hints: Arc::new(HintLimits { allow_private: true, in_flight: AtomicUsize::new(HINT_CONCURRENCY), ..HintLimits::default() }), ..State::default() };
        assert!(tags_for(&state, &hint_config(3), &Mirror::new(0, None, &[]), &path, "https://example.com").await.is_none());
    }

    #[tokio::test]
    async fn unknown_events_unparseable_ids_and_unconfigured_sites_get_no_tags() {
        let m = Mirror::new(0, None, &[]);
        let state = State::default();
        let config = Config { opengraph: Some(og()), ..Config::default() };
        let ghost = Nip19Event::new(event(9, 1, "x", vec![]).id).to_bech32().unwrap();
        assert!(tags_for(&state, &config, &m, &format!("/{ghost}"), "https://zap.stream").await.is_none());
        assert!(tags_for(&state, &config, &m, "/note1garbage", "https://zap.stream").await.is_none());
        assert!(tags_for(&state, &config, &m, "/", "https://zap.stream").await.is_none());
        assert!(tags_for(&state, &config, &m, "/streams", "https://zap.stream").await.is_none());
        assert!(tags_for(&state, &Config::default(), &m, &format!("/{ghost}"), "https://zap.stream").await.is_none());
    }

    #[tokio::test]
    async fn a_bare_nostr_address_path_resolves_through_nip05_and_is_cached() {
        use axum::routing::get;
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        let pk = keys(4).public_key().to_hex();
        let pk2 = pk.clone();
        let app = axum::Router::new().route("/nostr.json", get(move |q: axum::extract::Query<HashMap<String, String>>| {
            let (h, pk) = (h.clone(), pk2.clone());
            async move {
                h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                axum::Json(if q.get("name").map(String::as_str) == Some("erin") { json!({"names": {"erin": pk}}) } else { json!({"names": {}}) })
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let m = Mirror::new(0, None, &[]);
        save(&m, &profile_event(4, r#"{"name":"erin"}"#)).await;
        let state = State::default();
        let mut o = og();
        o.nip05_url = Some(format!("http://{addr}/nostr.json?name={{name}}"));
        o.nip05_domain = Some("zap.stream".into());
        let config = Config { opengraph: Some(o), static_paths: vec!["/".into(), "/streams".into()], ..Config::default() };
        let t = tags_for(&state, &config, &m, "/erin", "https://zap.stream").await.unwrap();
        assert_eq!(meta(&t, "og:title"), Some("erin's Profile"));
        assert!(tags_for(&state, &config, &m, "/erin", "https://zap.stream").await.is_some());
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(tags_for(&state, &config, &m, "/nobody", "https://zap.stream").await.is_none());
        assert!(tags_for(&state, &config, &m, "/streams", "https://zap.stream").await.is_none());
    }

    #[test]
    fn nostr_address_validation_rejects_private_domains_and_odd_names() {
        assert!(parse_address("alice", "example.com").is_some());
        assert!(parse_address("Alice", "Example.COM").is_some());
        assert!(parse_address("a b", "example.com").is_none());
        assert!(parse_address("a", "localhost").is_none());
        assert!(parse_address("a", "nas.local").is_none());
        assert!(parse_address("a", "192.168.1.1").is_none());
    }

    #[test]
    fn path_classification_matches_the_old_pages_middleware() {
        let defaults = OpenGraph::default().entity_prefixes;
        let entity = |p: &str| is_entity_path(p, &defaults);
        assert!(entity("/npub1abc") && entity("/e/nevent1abc") && entity("/p/nprofile1abc") && entity("/naddr1abc?x=1"));
        assert!(!entity("/streams") && !entity("/x/npub1abc"));
        assert!(is_address_path("/alice_1") && !is_address_path("/") && !is_address_path("/a/b") && !is_address_path("/a-b"));
        assert_eq!(last_segment("/e/nevent1abc?x=1"), Some("nevent1abc"));
    }

    #[tokio::test]
    async fn with_addresses_off_single_segment_paths_get_no_tags_and_no_lookup() {
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        let pk = keys(4).public_key().to_hex();
        let app = axum::Router::new().route("/nostr.json", axum::routing::get(move || {
            let (h, pk) = (h.clone(), pk.clone());
            async move {
                h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                axum::Json(json!({"names": {"erin": pk}}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let m = Mirror::new(0, None, &[]);
        let state = State::default();
        let og = OpenGraph { nip05_url: Some(format!("http://{addr}/nostr.json?name={{name}}")), nip05_domain: Some("example.com".into()), addresses: false, ..og() };
        let config = Config { opengraph: Some(og), ..Config::default() };
        assert!(tags_for(&state, &config, &m, "/erin", "https://example.com").await.is_none());
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn entity_prefixes_replace_the_default_entity_paths() {
        let prefixes = vec!["/v/".to_string(), "/live/".to_string()];
        assert!(is_entity_path("/v/nevent1abc", &prefixes) && is_entity_path("/live/naddr1abc?t=1", &prefixes));
        assert!(!is_entity_path("/naddr1abc", &prefixes) && !is_entity_path("/e/nevent1abc", &prefixes) && !is_entity_path("/v/streams", &prefixes));
    }

    #[test]
    fn merging_replaces_matching_head_tags_once_and_keeps_the_rest_escaped() {
        let head = "<title>Home - zap.stream</title>\n    <meta property=\"og:title\" content=\"old\" />\n    <meta name=\"description\" content=\"keep\" />\n    <link rel=\"canonical\" href=\"https://zap.stream\" />";
        let tags = Tags { metas: vec![pair("og:title", "A & B \"q\"")], title: Some("A & B".into()), canonical: Some("https://zap.stream/naddr1x".into()), json_ld: Some("{\"a\":\"</script>\"}".into()), ..Default::default() };
        let out = merge(head, &tags);
        assert_eq!(out.matches("og:title").count(), 1);
        assert_eq!(out.matches("<title>").count(), 1);
        assert!(out.contains("<title>A &amp; B</title>"));
        assert!(out.contains("content=\"A &amp; B &quot;q&quot;\""));
        assert_eq!(out.matches("rel=\"canonical\"").count(), 1);
        assert!(out.contains("naddr1x") && out.contains("name=\"description\" content=\"keep\""));
        assert_eq!(out.matches("</script>").count(), 1);
    }
}

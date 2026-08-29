//! Resolve Meta's build archive for a revision: prints whether the revision was
//! published for the app and, if so, the signed CDN URL its zip lives at. Downloads
//! nothing — the archive is ~370 MB and belongs in a streaming tool, not in memory.
//!
//! Run: cargo run -p wa-fetch --example btarchive -- 1046341789 whatsapp

use wa_fetch::{ArchiveApp, ArchiveLookup};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let revision: u64 = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: btarchive <client_revision> [app]"))?
        .parse()?;
    let app = match args.next() {
        Some(name) => {
            ArchiveApp::parse(&name).ok_or_else(|| anyhow::anyhow!("unknown app {name:?}"))?
        }
        None => ArchiveApp::WhatsApp,
    };

    match wa_fetch::lookup_archive(revision, app)? {
        ArchiveLookup::Published(loc) => {
            println!("published:   {} / {}", loc.revision, loc.app.as_str());
            println!("request:     {}", loc.request_url);
            println!("payload host:{}", loc.payload_host);
            println!("payload url: {}", loc.payload_url);
        }
        ArchiveLookup::NotPublished { revision, app } => {
            println!("not published: {revision} / {}", app.as_str());
        }
    }
    Ok(())
}

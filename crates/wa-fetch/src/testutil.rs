//! Shared test-only helpers: a minimal local HTTP/1.1 server so download +
//! discovery can be exercised without real network access.
#![cfg(test)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

/// Spawn a server routing `path -> (status, body)`; returns its `http://addr` base.
/// Unknown paths return 404. One connection per request (`Connection: close`).
pub(crate) fn spawn_server(routes: HashMap<String, (u16, Vec<u8>)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let routes = Arc::new(routes);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let routes = routes.clone();
            std::thread::spawn(move || handle(stream, &routes));
        }
    });
    format!("http://{addr}")
}

fn handle(mut stream: TcpStream, routes: &HashMap<String, (u16, Vec<u8>)>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => return,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let req = String::from_utf8_lossy(&buf);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let (status, body) = routes
        .get(&path)
        .cloned()
        .unwrap_or((404, b"not found".to_vec()));
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&body);
}

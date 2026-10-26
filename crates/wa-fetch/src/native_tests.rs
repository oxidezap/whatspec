use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use ureq::tls::{Certificate, RootCerts};

const ROOT: &[u8] = include_bytes!("../tests/fixtures/root.der");
const CERT: &[u8] = include_bytes!("../tests/fixtures/localhost.der");
const KEY: &[u8] = include_bytes!("../tests/fixtures/localhost-key.der");

fn trusted_client() -> UreqClient {
    UreqClient::with_tls_config(
        tls_config_builder()
            .root_certs(RootCerts::new_with_certs(&[Certificate::from_der(ROOT)]))
            .build(),
    )
}

fn server(
    version: &'static rustls::SupportedProtocolVersion,
    responses: Vec<String>,
) -> (String, JoinHandle<Vec<String>>) {
    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(CERT.to_vec())],
                rustls::pki_types::PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
            )
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let worker = thread::spawn(move || {
        let config = Arc::new(config);
        let mut requests = Vec::new();
        'connections: for response in responses {
            let deadline = Instant::now() + Duration::from_secs(10);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "client did not connect");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let connection = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut buffer = [0; 1024];
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => continue 'connections,
                    Ok(length) => request.extend_from_slice(&buffer[..length]),
                }
                assert!(request.len() <= 16 * 1024);
            }
            assert_eq!(stream.conn.protocol_version(), Some(version.version));
            requests.push(String::from_utf8(request).unwrap());
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
        requests
    });
    (url, worker)
}

#[test]
fn default_config_keeps_webpki_and_certificate_verification() {
    let config = tls_config();
    assert!(matches!(config.root_certs(), RootCerts::WebPki));
    assert!(!config.disable_verification());
    assert!(config.use_sni());
    assert!(config.client_cert().is_none());
}

#[test]
fn tls12_and_tls13_preserve_http_status_and_body() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (url, worker) = server(
            version,
            vec![
                "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                    .into(),
            ],
        );
        let response = trusted_client().get(&url, &[], 6).unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"hello");
        assert_eq!(worker.join().unwrap().len(), 1);
    }
}

#[test]
fn rejects_untrusted_certificate() {
    let (url, worker) = server(&rustls::version::TLS13, vec![String::new()]);
    let error = UreqClient::new().get(&url, &[], 16).unwrap_err();
    assert!(error.to_string().contains("certificate"), "{error}");
    assert!(worker.join().unwrap().is_empty());
}

#[test]
fn rejects_wrong_hostname_even_with_trusted_root() {
    let (url, worker) = server(&rustls::version::TLS13, vec![String::new()]);
    let error = trusted_client()
        .get(&url.replace("localhost", "127.0.0.1"), &[], 16)
        .unwrap_err();
    assert!(error.to_string().contains("certificate"), "{error}");
    assert!(worker.join().unwrap().is_empty());
}

#[test]
fn get_and_redirect_probe_enforce_body_limits() {
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    let (url, worker) = server(
        &rustls::version::TLS13,
        vec![response.into(), response.into()],
    );
    let client = trusted_client();
    assert!(client.get(&url, &[], 4).is_err());
    assert!(client.get_redirect(&url, &[], 4).is_err());
    assert_eq!(worker.join().unwrap().len(), 2);
}

#[test]
fn redirect_probe_stops_and_normal_get_follows() {
    let redirect =
        "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let (url, worker) = server(
        &rustls::version::TLS13,
        vec![
            redirect.into(),
            redirect.into(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".into(),
        ],
    );
    let client = trusted_client();
    let probe = client.get_redirect(&url, &[], 16).unwrap();
    assert_eq!(probe.status, 302);
    assert_eq!(probe.location.as_deref(), Some("/final"));
    assert_eq!(client.get(&url, &[], 16).unwrap().body, b"ok");
    assert_eq!(worker.join().unwrap().len(), 3);
}

#[test]
fn redirects_do_not_forward_authorization_across_origins() {
    let (destination, destination_worker) = server(
        &rustls::version::TLS13,
        vec!["HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".into()],
    );
    let (source, source_worker) = server(
        &rustls::version::TLS13,
        vec![format!(
            "HTTP/1.1 302 Found\r\nLocation: {destination}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )],
    );
    trusted_client()
        .get(&source, &[("Authorization", "Bearer fixture")], 16)
        .unwrap();
    let source = source_worker.join().unwrap();
    let destination = destination_worker.join().unwrap();
    assert!(
        source[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture")
    );
    assert!(
        !destination[0]
            .to_ascii_lowercase()
            .contains("authorization:")
    );
}

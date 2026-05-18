use enclavia::{Client, Pcrs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:8080".to_string());

    println!("[test] Connecting to {url}...");

    let client = Client::builder(&url)
        .pcrs(Pcrs {
            pcr0: vec![],
            pcr1: vec![],
            pcr2: vec![],
        })
        .debug_mode(true)
        .build()
        .await?;

    println!("[test] Connected and attested!");

    let resp = client
        .get("/")
        .header("Host", "localhost")
        .send()
        .await?;

    println!("[test] Status: {}", resp.status());
    println!("[test] Headers: {:?}", resp.headers());
    println!("[test] Body: {}", resp.text()?);

    println!("\n[test] SUCCESS");
    Ok(())
}

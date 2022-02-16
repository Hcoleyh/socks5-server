use tokio;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    socks5_server::run("127.0.0.1:1080").await
}

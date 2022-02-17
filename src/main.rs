use tokio;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    match parse_args() {
        Ok((addr, port)) => 
            socks5_server::run(&format!("{}:{}", addr, port)).await,
        _ => {
            help();
            Ok(())
        }
    }
}

fn parse_args() -> Result<(String, String), lexopt::Error> {
    use lexopt::prelude::*;

    let mut addr = String::from("127.0.0.1");
    let mut port = String::from("1080");

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('b') => {
                addr = parser.value()?.into_string()?;
            },
            Short('p') => {
                port = parser.value()?.into_string()?;
            },
            Long("help") => help(),
            _ => help()
        }
    }

    Ok((addr, port))
}

fn help() {
    println!("Usage: socks5_server [-b BIND_ADDR] [-p PORT]");
    std::process::exit(0);
}

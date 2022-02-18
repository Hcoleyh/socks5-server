use tokio::net::{TcpListener, TcpStream};
use tokio::io::{copy_bidirectional, AsyncWriteExt, AsyncReadExt};
use anyhow::Result;

#[derive(Clone, Copy)]
enum Method {
    NOAUTH = 0x00,
    //GSSAPI = 0x01,
    //PASSWD = 0x02,
    ERROR  = 0xff
}

struct Connection {
    stream: TcpStream,
    version: u8,
}

enum Command {
    CONNECT = 0x01,
    //BIND = 0x02,
    //UDP = 0x03,
    Unsupported = 0x04,
}

enum CommandRep {
    SUCCEEDED = 0x00,
    ServerError = 0x01,
    //RuleSetNotAllowed = 0x02,
    //NetworkUnreached = 0x03,
    //HostUnreached = 0x04,
    ConnectionRefused = 0x05,
    //TTLExpired = 0x06,
    CommandUnsupported = 0x07,
    AddrTypeUnsupported = 0x08,
}

enum AddrType {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
    Unsupported = 0x05,
}

pub async fn run(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut connection = Connection::new(stream);
            let _ = connection.handle().await;
        });
    }
}

impl Connection {

    pub fn new(stream: TcpStream) -> Self {
        Connection {
            stream,
            version: 5u8
        }
    }

    async fn handle(&mut self) -> Result<()> {
        let method = self.negotiate_method().await?;
        self.reply_method(method).await?;

        self.auth(method).await;

        self.handle_command().await
    }

    async fn handle_command(&mut self) -> Result<()> {
        use CommandRep::{ServerError, CommandUnsupported};
        let mut buf = [0u8; 3];

        self.stream.read_exact(&mut buf).await?;
        if buf[0] != self.version {
            return self.reply_command(ServerError).await;
        }

        match buf[1].into() {
            Command::CONNECT => {
                self.handle_connect_command().await
            },
            Command::Unsupported => {
                self.reply_command(CommandUnsupported).await
            },
        }
    }

    async fn handle_connect_command(&mut self) -> Result<()> {
        let addr = self.read_addr().await?;

        match TcpStream::connect(addr).await {
            Err(_) => {
                self.reply_command(CommandRep::ConnectionRefused).await
            },
            Ok(mut connection) => {
                self.reply_command(CommandRep::SUCCEEDED).await?;
                copy_bidirectional(&mut self.stream, &mut connection).await?;
                Ok(())
            },
        }
    }

    async fn read_addr(&mut self) -> Result<std::net::SocketAddr> {
        use std::net::SocketAddr;

        let addr_type: AddrType = self.stream.read_u8().await?.into();

        match addr_type {
            AddrType::V4 => {
                let mut addr = [0u8; 4];
                self.stream.read_exact(&mut addr).await?;
                let port = self.stream.read_u16().await?;

                Ok(SocketAddr::from((addr, port)))
            },
            AddrType::V6 => {
                let mut addr = [0u8; 16];
                self.stream.read_exact(&mut addr).await?;
                let port = self.stream.read_u16().await?;

                Ok(SocketAddr::from((addr, port)))
            },
            AddrType::Domain => {
                let len = self.stream.read_u8().await?;
                let mut domain = Vec::with_capacity(len as usize);
                self.stream.read_exact(&mut domain).await?;
                let port = self.stream.read_u16().await?;

                use std::str::FromStr;
                Ok(SocketAddr::from_str(&format!("{:?}:{}", domain.as_slice(), port))?)
            }
            _ => {
                self.reply_command(CommandRep::AddrTypeUnsupported).await?;
                Err(anyhow::anyhow!("Unsupported Address Type"))
            }
        }
    }

    async fn reply_command(&mut self, rep: CommandRep) -> Result<()> {
        self.stream.write_u16(to_u16(self.version, rep as u8)).await?;
        self.stream.write_u16(AddrType::V4 as u16).await?;
        self.stream.write_u32(0u32).await?;
        self.stream.write_u16(0u16).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn negotiate_method(&mut self) -> Result<Method> {
        let mut buf = [0u8; 255];

        self.stream.read_exact(&mut buf[..2]).await?;
        if buf[0] != self.version {
            return Ok(Method::ERROR);
        }

        let n_methods = buf[1] as usize;
        self.stream.read_exact(&mut buf[..n_methods]).await?;
        if !buf[..n_methods].contains(&(Method::NOAUTH as u8)) {
            return Ok(Method::ERROR);
        }

        Ok(Method::NOAUTH)
    }

    async fn reply_method(&mut self, method: Method) -> Result<()> {
        self.stream.write_u16(to_u16(self.version, method as u8)).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn auth(&mut self, method: Method) {
        match method {
            Method::NOAUTH => (),
            _ => (),
        }
    }

}

impl From<u8> for Command {
    fn from(c: u8) -> Self {
        match c {
            1u8 => Command::CONNECT,
            _ => Command::Unsupported
        }
    }
}

impl From<u8> for AddrType {
    fn from (t: u8) -> Self {
        match t {
            1u8 => AddrType::V4,
            3u8 => AddrType::Domain,
            4u8 => AddrType::V6,
            _ => AddrType::Unsupported,
        }
    }
}

fn to_u16(a: u8, b: u8) -> u16 {
    ((a as u16) << 8) + b as u16
}

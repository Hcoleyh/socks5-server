use anyhow::Result;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy)]
enum Method {
    Noauth = 0x00,
    //GSSAPI = 0x01,
    Passwd = 0x02,
    Error = 0xff,
}

enum AuthMethod {
    Passwd = 0x01,
}

struct Connection {
    stream: TcpStream,
    version: u8,
}

enum Command {
    Connect = 0x01,
    //BIND = 0x02,
    //UDP = 0x03,
    Unsupported = 0x04,
}

enum CommandRep {
    Succeeded = 0x00,
    //ServerError = 0x01,
    RuleSetNotAllowed = 0x02,
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

enum Stage {
    Method,
    Auth,
    Command,
}

pub async fn run(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut connection = Connection::new(stream);
            match connection.handle().await {
                Err(e) => match e.downcast::<anyhow::Error>() {
                    Err(_) => (),
                    _ => (),
                },
                _ => (),
            };
        });
    }
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        Connection {
            stream,
            version: 5u8,
        }
    }

    async fn handle(&mut self) -> Result<()> {
        let method = self.negotiate_method().await?;
        self.reply_method(method).await?;

        self.auth(method).await?;

        self.handle_command().await
    }

    async fn handle_command(&mut self) -> Result<()> {
        use CommandRep::{CommandUnsupported, RuleSetNotAllowed};
        let mut buf = [0u8; 3];

        self.stream.read_exact(&mut buf).await?;
        if buf[0] != self.version {
            return self.reply_command(RuleSetNotAllowed).await;
        }

        match buf[1].into() {
            Command::Connect => self.handle_connect_command().await,
            _ => self.reply_command(CommandUnsupported).await,
        }
    }

    async fn handle_connect_command(&mut self) -> Result<()> {
        let addr = self.read_addr().await?;

        match TcpStream::connect(addr).await {
            Err(_) => self.reply_command(CommandRep::ConnectionRefused).await,
            Ok(mut connection) => {
                self.reply_command(CommandRep::Succeeded).await?;
                copy_bidirectional(&mut self.stream, &mut connection).await?;
                Ok(())
            }
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
            }
            AddrType::V6 => {
                let mut addr = [0u8; 16];
                self.stream.read_exact(&mut addr).await?;
                let port = self.stream.read_u16().await?;

                Ok(SocketAddr::from((addr, port)))
            }
            AddrType::Domain => {
                let domain = self.read_variable(Stage::Command).await?;
                let port = self.stream.read_u16().await?;

                use std::str::FromStr;
                Ok(SocketAddr::from_str(&format!(
                    "{:?}:{}",
                    domain.as_slice(),
                    port
                ))?)
            }
            _ => {
                self.reply_command(CommandRep::AddrTypeUnsupported).await?;
                anyhow::bail!("Unsupported address type")
            }
        }
    }

    async fn read_variable(&mut self, stage: Stage) -> Result<Vec<u8>> {
        let len = match self.stream.read_u8().await? {
            0 => {
                match stage {
                    Stage::Command => self.reply_command(CommandRep::RuleSetNotAllowed).await?,
                    Stage::Method => self.reply_method(Method::Error).await?,
                    Stage::Auth => self.reply_auth(AuthMethod::Passwd, false).await?,
                }
                anyhow::bail!("Error lens of variable field")
            }
            n => n,
        } as usize;

        let mut buf = vec![0; len];
        self.stream.read_exact(&mut buf).await?;

        Ok(buf)
    }

    async fn reply_command(&mut self, rep: CommandRep) -> Result<()> {
        let buf = vec![
            self.version,
            rep as u8,
            0,
            AddrType::V4 as u8,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        self.stream.write_all(&buf).await?;
        //self.stream
        //    .write_u16(to_u16(self.version, rep as u8))
        //    .await?;
        //self.stream.write_u16(AddrType::V4 as u16).await?;
        //self.stream.write_u32(0u32).await?;
        //self.stream.write_u16(0u16).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn negotiate_method(&mut self) -> Result<Method> {
        if self.stream.read_u8().await? != self.version {
            return Ok(Method::Error);
        }

        let buf = self.read_variable(Stage::Method).await?;
        if buf.contains(&(Method::Passwd as u8)) {
            return Ok(Method::Passwd);
        }
        if buf.contains(&(Method::Noauth as u8)) {
            return Ok(Method::Noauth);
        }

        Ok(Method::Error)
    }

    async fn reply_method(&mut self, method: Method) -> Result<()> {
        self.stream
            .write_u16(to_u16(self.version, method as u8))
            .await?;
        self.stream.flush().await?;

        match method {
            Method::Error => anyhow::bail!("Error method"),
            _ => Ok(()),
        }
    }

    async fn auth(&mut self, method: Method) -> Result<()> {
        match method {
            Method::Noauth => Ok(()),
            Method::Passwd => self.auth_passwd().await,
            _ => unreachable!(),
        }
    }

    async fn reply_auth(&mut self, method: AuthMethod, rep: bool) -> Result<()> {
        self.stream
            .write_u16(to_u16(method as u8, !rep as u8))
            .await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn auth_passwd(&mut self) -> Result<()> {
        self.stream.read_u8().await?;
        let username = self.read_variable(Stage::Auth).await?;
        let password = self.read_variable(Stage::Auth).await?;

        let simple = vec![49, 50, 51];
        if username != simple || password != simple {
            self.reply_auth(AuthMethod::Passwd, false).await?;
            anyhow::bail!("Auth failed");
        }

        self.reply_auth(AuthMethod::Passwd, true).await
    }
}

impl From<u8> for Command {
    fn from(c: u8) -> Self {
        match c {
            1u8 => Command::Connect,
            _ => Command::Unsupported,
        }
    }
}

impl From<u8> for AddrType {
    fn from(t: u8) -> Self {
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

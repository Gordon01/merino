use crate::*;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct SOCKClient<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    pub(crate) stream: T,
    auth_nmethods: u8,
    auth_methods: Arc<Vec<u8>>,
    authed_users: Arc<Vec<User>>,
    whitelisted: bool,
    socks_version: u8,
    timeout: Option<Duration>,
}

impl<T> SOCKClient<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Create a new SOCKClient
    pub fn new(
        stream: T,
        authed_users: Arc<Vec<User>>,
        auth_methods: Arc<Vec<u8>>,
        whitelisted: bool,
        timeout: Option<Duration>,
    ) -> Self {
        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0,
            authed_users,
            auth_methods,
            whitelisted,
            timeout,
        }
    }

    /// Create a new SOCKClient with no auth
    pub fn new_no_auth(stream: T, timeout: Option<Duration>) -> Self {
        // FIXME: use option here
        let authed_users: Arc<Vec<User>> = Arc::new(Vec::new());
        let no_auth: Vec<u8> = vec![AuthMethods::NoAuth as u8];
        let auth_methods: Arc<Vec<u8>> = Arc::new(no_auth);

        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0,
            authed_users,
            auth_methods,
            whitelisted: false,
            timeout,
        }
    }

    /// Mutable getter for inner stream
    pub fn stream_mut(&mut self) -> &mut T {
        &mut self.stream
    }

    /// Check if username + password pair are valid
    fn authed(&self, user: &User) -> bool {
        self.authed_users.contains(user)
    }

    /// Shutdown a client
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    pub async fn init(&mut self) -> Result<(), MerinoError> {
        debug!("New connection");
        let mut header = [0u8; 2];
        // Read a byte from the stream and determine the version being requested
        self.stream.read_exact(&mut header).await?;

        self.socks_version = header[0];
        self.auth_nmethods = header[1];

        trace!(
            "Version: {} Auth nmethods: {}",
            self.socks_version,
            self.auth_nmethods
        );

        match self.socks_version {
            SOCKS_VERSION => {
                // Authenticate w/ client
                self.auth().await?;
                // Handle requests
                self.handle_client().await?;
            }
            _ => {
                warn!("Init: Unsupported version: SOCKS{}", self.socks_version);
                self.shutdown().await?;
            }
        }

        Ok(())
    }

    async fn auth(&mut self) -> Result<(), MerinoError> {
        debug!("Authenticating");
        // Get valid auth methods
        let methods = self.get_avalible_methods().await?;
        trace!("methods: {:?}", methods);

        let mut response = [0u8; 2];

        // Set the version in the response
        response[0] = SOCKS_VERSION;

        if methods.contains(&(AuthMethods::UserPass as u8)) {
            // Set the default auth method (NO AUTH)
            response[1] = AuthMethods::UserPass as u8;

            debug!("Sending USER/PASS packet");
            self.stream.write_all(&response).await?;

            let mut header = [0u8; 2];

            // Read a byte from the stream and determine the version being requested
            self.stream.read_exact(&mut header).await?;

            // debug!("Auth Header: [{}, {}]", header[0], header[1]);

            // Username parsing
            let ulen = header[1] as usize;

            let mut username = vec![0; ulen];

            self.stream.read_exact(&mut username).await?;

            // Password Parsing
            let mut plen = [0u8; 1];
            self.stream.read_exact(&mut plen).await?;

            let mut password = vec![0; plen[0] as usize];
            self.stream.read_exact(&mut password).await?;

            let username = String::from_utf8_lossy(&username).to_string();
            let password = String::from_utf8_lossy(&password).to_string();

            let user = User { username, password };

            // Authenticate passwords
            if self.authed(&user) {
                debug!("Access Granted. User: {}", user.username);
                let response = [1, ResponseCode::Success as u8];
                self.stream.write_all(&response).await?;
            } else {
                debug!("Access Denied. User: {}", user.username);
                let response = [1, ResponseCode::Failure as u8];
                self.stream.write_all(&response).await?;

                // Shutdown
                self.shutdown().await?;
            }

            Ok(())
        } else if methods.contains(&(AuthMethods::NoAuth as u8)) {
            // set the default auth method (no auth)
            response[1] = AuthMethods::NoAuth as u8;
            debug!("Sending NOAUTH packet");
            self.stream.write_all(&response).await?;
            debug!("NOAUTH sent");
            Ok(())
        } else {
            warn!("Client has no suitable Auth methods!");
            response[1] = AuthMethods::NoMethods as u8;
            self.stream.write_all(&response).await?;
            self.shutdown().await?;

            Err(MerinoError::Socks(ResponseCode::RuleFailure))
        }
    }

    /// Handles a client
    pub async fn handle_client(&mut self) -> Result<usize, MerinoError> {
        debug!("Starting to relay data");

        let req = SOCKSReq::from_stream(&mut self.stream).await?;

        if req.addr_type == AddrType::V6 {}

        // Log Request
        let displayed_addr = pretty_print_addr(&req.addr_type, &req.addr);
        info!(
            "New Request: Command: {:?} Addr: {}, Port: {}",
            req.command, displayed_addr, req.port
        );

        // Respond
        match req.command {
            // Use the Proxy to connect to the specified addr/port
            SockCommand::Connect => {
                debug!("Handling CONNECT Command");

                let sock_addr = addr_to_socket(&req.addr_type, &req.addr, req.port)?;

                trace!("Connecting to: {:?}", sock_addr);

                let time_out = if let Some(time_out) = self.timeout {
                    time_out
                } else {
                    Duration::from_millis(50)
                };

                let mut target =
                    timeout(
                        time_out,
                        async move { TcpStream::connect(&sock_addr[..]).await },
                    )
                    .await
                    .map_err(|_| MerinoError::Socks(ResponseCode::AddrTypeNotSupported))
                    .map_err(|_| MerinoError::Socks(ResponseCode::AddrTypeNotSupported))??;

                trace!("Connected!");

                SocksReply::new(ResponseCode::Success)
                    .send(&mut self.stream)
                    .await?;

                trace!("copy bidirectional");
                match tokio::io::copy_bidirectional(&mut self.stream, &mut target).await {
                    // ignore not connected for shutdown error
                    Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                        trace!("already closed");
                        Ok(0)
                    }
                    Err(e) => Err(MerinoError::Io(e)),
                    Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
                }
            }
            SockCommand::Bind => Err(MerinoError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Bind not supported",
            ))),
            SockCommand::UdpAssosiate => Err(MerinoError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UdpAssosiate not supported",
            ))),
        }
    }

    /// Return the avalible methods based on `self.auth_nmethods`
    async fn get_avalible_methods(&mut self) -> io::Result<Vec<u8>> {
        let mut methods: Vec<u8> = Vec::with_capacity(self.auth_nmethods as usize);
        for _ in 0..self.auth_nmethods {
            let mut method = [0u8; 1];
            self.stream.read_exact(&mut method).await?;
            if self.auth_methods.contains(&method[0]) {
                methods.append(&mut method.to_vec());
            }
        }

        // Add NoAuth method if peer is whitelisted to allow connection in every confiuration
        let no_auth = super::AuthMethods::NoAuth as u8;
        if self.whitelisted && !methods.contains(&no_auth) {
            debug!("Client is whitelisted");
            methods.push(no_auth);
        }

        Ok(methods)
    }
}

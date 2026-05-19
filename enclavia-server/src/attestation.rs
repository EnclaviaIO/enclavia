/// RAII guard that ensures `nsm_exit(fd)` is called when dropped.
struct NsmGuard(i32);

impl Drop for NsmGuard {
    fn drop(&mut self) {
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(self.0);
    }
}

pub fn get_attestation_with_data(
    handshake_hash: &[u8],
    user_data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd == -1 {
        return Err(Box::new(std::io::Error::other("Failed to initialize NSM")));
    }
    let _guard = NsmGuard(fd);

    let request = Request::Attestation {
        user_data: Some(From::from(user_data.to_vec())),
        nonce: Some(From::from(handshake_hash.to_vec())),
        public_key: None,
    };

    let response = match nsm_process_request(fd, request) {
        Response::Attestation { document } => document,
        Response::Error(error) => return Err(Box::new(std::io::Error::other(format!("Unexpected response from NSM: {error:?}")))),
        _ => return Err(Box::new(std::io::Error::other("Unexpected response from NSM"))),
    };

    Ok(response)
}

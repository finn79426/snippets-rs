use alloy::signers::local::PrivateKeySigner;

pub type WalletAddress = String;
pub type PrivateKey = String;

/// Generates a new random ECDSA wallet address and private key.
///
/// # Arguments
/// * `None`
///
/// # Returns
/// * `WalletAddress` - The generated wallet address.
/// * `PrivateKey` - The generated private key.
pub fn generate() -> (WalletAddress, PrivateKey) {
    let signer = PrivateKeySigner::random();

    let address = format!("{:?}", signer.address());
    let private_key = hex::encode(signer.to_bytes());

    (address, private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let (address, private_key) = generate();
        assert!(!address.is_empty());
        assert!(!private_key.is_empty());
        assert!(address.len() == 42);
        assert!(private_key.len() == 64);
        assert!(address.starts_with("0x"));
        assert!(!private_key.starts_with("0x"));
        assert!(address.chars().skip(2).all(|c| c.is_ascii_hexdigit()));
        assert!(private_key.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

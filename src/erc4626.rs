/// ERC-4626 helper utilities.
///
/// This module contains helpers to build an `alloy` `Provider` from a RPC URL and a
/// lightweight probe to check whether a contract implements the ERC-4626 vault API
/// (by attempting to call `totalAssets()` and decode the return value).
///
/// The checks implemented here are convenient for scripting and quick inspection,
/// but they are NOT foolproof—see the cautions in `build_provider` and `is_erc4626`.
///
/// Example:
/// ```no_run
/// # async fn example() -> eyre::Result<()> {
/// let provider = snippet_rs::erc_4626::build_provider("https://eth.llamarpc.com").await?;
/// let is_vault = snippet_rs::erc_4626::is_erc4626("0xDcEe70654261AF21C44c093C300eD3Bb97b78192").await;
/// println!("is erc4626: {}", is_vault);
/// # Ok(())
/// # }
/// ```
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::primitives::{Address, TxKind, Bytes};
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy::rpc::types::eth::TransactionRequest;
use alloy::rpc::types::TransactionInput;
use eyre::{Result, bail};
use std::sync::Arc;
use url::Url;

sol! {
    function allowance(address,address) view returns (uint256);
    function approve(address,uint256) returns (bool);
    function asset() view returns (address);
    function balanceOf(address) view returns (uint256);
    function convertToAssets(uint256) view returns (uint256);
    function convertToShares(uint256) view returns (uint256);
    function decimals() view returns (uint8);
    function deposit(uint256,address) returns (uint256);
    function maxDeposit(address) view returns (uint256);
    function maxMint(address) view returns (uint256);
    function maxRedeem(address) view returns (uint256);
    function maxWithdraw(address) view returns (uint256);
    function mint(uint256,address) returns (uint256);
    function name() view returns (string);
    function previewDeposit(uint256) view returns (uint256);
    function previewMint(uint256) view returns (uint256);
    function previewRedeem(uint256) view returns (uint256);
    function previewWithdraw(uint256) view returns (uint256);
    function redeem(uint256,address,address) returns (uint256);
    function symbol() view returns (string);
    function totalAssets() view returns (uint256);
    function totalSupply() view returns (uint256);
    function transfer(address,uint256) returns (bool);
    function transferFrom(address,address,uint256) returns (bool);
    function withdraw(uint256,address,address) returns (uint256);
}


/// Build a `Provider` from an RPC URL.
///
/// # Arguments
/// * `rpc_url` - A string containing the RPC endpoint URL. Common schemes are `http://`,
///   `https://`, `ws://`, and `wss://`.
///
/// # Returns
/// * `Result<Arc<dyn Provider>>` - A dynamically-dispatched `Provider` wrapped in `Arc`.
///
/// # Notes / Warnings
/// *`build_provider` does NOT guarantee that the provided RPC URL points to a
///    running or correctly functioning RPC node. It only parses the URL and
///    constructs an appropriate `Provider` instance based on common URL schemes.
///    No network connectivity test is performed; callers should handle possible
///    runtime errors when using the returned `Provider`.
pub async fn build_provider(rpc_url: &str) -> Result<Arc<dyn Provider>> {
    let parsed_rpc_url = Url::parse(rpc_url)?;

    if parsed_rpc_url.scheme().starts_with("http") {
        let provider = ProviderBuilder::new().connect_http(parsed_rpc_url);
        Ok(Arc::new(provider))
    } else if parsed_rpc_url.scheme().starts_with("ws") {
        let provider = ProviderBuilder::new().connect_ws(WsConnect::new(parsed_rpc_url.as_str())).await?;
        Ok(Arc::new(provider))
    } else {
        bail!("Unsupported RPC URL scheme: {}", parsed_rpc_url.scheme());
    }
}

/// Probe whether a contract appears to implement ERC-4626 standard.
///
/// # Arguments
/// * `address` - Contract address string (0x-prefixed or not).
///
/// # Returns
/// * `bool` - `true` if the contract is highly possible to implemented ERC-4626.
///
/// # Notes / Warnings
/// 1. There is no 100% reliable on-chain-only method to prove a contract fully
///    implements the ERC-4626 specification. This probe only checks for the
///    presence of a `totalAssets()` function with a compatible signature. A
///    malicious or misconfigured contract could implement a function with the
///    same signature but different semantics, causing false positives.
/// 2. Because of the above, this method is NOT RECOMMENDED for production
///    security checks or to grant privileges. Use it only as a best-effort
///    heuristic for discovery and follow up with stronger verification.
pub async fn is_erc4626(address: &str) -> bool{
    let provider = build_provider("https://eth.llamarpc.com").await.unwrap();
    let contract_address = address.parse::<Address>().unwrap();

    let calldata: Bytes = totalAssetsCall.abi_encode().into();
    let tx = TransactionRequest {
        to: Some(TxKind::Call(contract_address)),
        input: TransactionInput{
            data: Some(calldata),
            ..Default::default()
        },
        ..Default::default()
    };

    let result = provider.call(tx).await.unwrap();
    match totalAssetsCall::abi_decode_returns(&result) {
        Ok(_) => true,
        Err(_) => false,
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_build_provider() {
        assert!(build_provider("https://eth.llamarpc.com").await.is_ok());
        assert!(build_provider("wss://ethereum-rpc.publicnode.com").await.is_ok());
        assert!(build_provider("ftp://example.com").await.is_err());
    }

    #[tokio::test]
    async fn test_is_erc4626() {
        assert!(is_erc4626("0xDcEe70654261AF21C44c093C300eD3Bb97b78192").await);
        assert!(!is_erc4626("0x0000000000000000000000000000000000000000").await);
    }
}
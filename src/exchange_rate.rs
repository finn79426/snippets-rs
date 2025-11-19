use chrono::{Local, NaiveDate};
use once_cell::sync::Lazy;
use serde_json::Value;
use std::time::Duration;

/// Exchange-rate helpers and HTTP utilities.
///
/// Provides a shared HTTP client and convenience functions to fetch and parse
/// exchange rate data from public CDN endpoints. The `get` function resolves a
/// `base` currency to a `quote` currency on a given `date` (or `latest`).
///
/// Example:
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let rate = snippet_rs::exchange_rate::get("BTC", "TWD", "latest").await?;
/// println!("BTC/TWD = {}", rate);
/// # Ok(())
/// # }
/// ```

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build reqwest::Client")
});

/// Get an exchange rate for (`base`/`quote`) at `date`.
///
/// # Arguments
/// * `base` - Base currency symbol (e.g. "BTC").
/// * `quote` - Quote currency symbol (e.g. "TWD").
/// * `date` - Date in `YYYY-MM-DD` format or the literal `"latest"`.
///
/// # Returns
/// * `Result<f64, Box<dyn std::error::Error>>` - The exchange rate if found.
///
/// # Behavior
/// - Attempts two known CDN URLs for the requested (`base`/`date`).
/// - Parses the JSON and looks up `json[base][quote]`.
/// - Returns an error if the rate cannot be found or on network/parse errors.
pub async fn get(base: &str, quote: &str, date: &str) -> Result<f64, Box<dyn std::error::Error>> {
    let base_lower = base.to_lowercase();
    let quote_lower = quote.to_lowercase();

    let parsed_date = if date == "latest" {
        Local::now().date_naive().format("%Y-%m-%d").to_string()
    } else {
        NaiveDate::parse_from_str(date, "%Y-%m-%d")?.to_string()
    };

    let url1 = format!(
        "https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@{}/v1/currencies/{}.min.json",
        parsed_date, base_lower
    );
    let url2 = format!(
        "https://{}.currency-api.pages.dev/v1/currencies/{}.min.json",
        parsed_date, base_lower
    );

    let resp = match HTTP_CLIENT.get(&url1).send().await {
        Ok(r) => r,
        Err(_) => HTTP_CLIENT.get(&url2).send().await?,
    };

    let json = resp.json::<Value>().await?;

    let rate = json
        .get(&base_lower)
        .and_then(|c| c.get(&quote_lower))
        .and_then(|v| v.as_f64())
        .ok_or_else(|| format!("Could not find rate for {} -> {}", base, quote))?;

    Ok(rate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_get() {
        let btc_usd_latest = get("BTC", "USD", "latest").await;
        let eth_usd_latest = get("ETH", "USD", "latest").await;
        let btc_cad_latest = get("BTC", "CAD", "latest").await;
        let btc_twd_latest = get("BTC", "TWD", "latest").await;
        let usdt_usd_latest = get("USDT", "USD", "latest").await;
        let usdc_usd_latest = get("USDC", "USD", "latest").await;
        let cad_usd_latest = get("CAD", "USD", "latest").await;
        let twd_usd_latest = get("TWD", "USD", "latest").await;
        let btc_usd_2025 = get("BTC", "USD", "2025-01-01").await;
        let eth_usd_2025 = get("ETH", "USD", "2025-01-01").await;
        let cad_usd_2025 = get("CAD", "USD", "2025-01-01").await;
        let twd_usd_2025 = get("TWD", "USD", "2025-01-01").await;

        assert!(btc_usd_latest.is_ok());
        assert!(eth_usd_latest.is_ok());
        assert!(btc_cad_latest.is_ok());
        assert!(btc_twd_latest.is_ok());
        assert!(usdt_usd_latest.is_ok());
        assert!(usdc_usd_latest.is_ok());
        assert!(cad_usd_latest.is_ok());
        assert!(twd_usd_latest.is_ok());
        assert!(btc_usd_2025.is_ok());
        assert!(eth_usd_2025.is_ok());
        assert!(cad_usd_2025.is_ok());
        assert!(twd_usd_2025.is_ok());

        assert!(btc_usd_latest.unwrap() > 0.0);
        assert!(eth_usd_latest.unwrap() > 0.0);
        assert!(btc_cad_latest.unwrap() > 0.0);
        assert!(btc_twd_latest.unwrap() > 0.0);
        assert!(usdt_usd_latest.unwrap() > 0.0);
        assert!(usdc_usd_latest.unwrap() > 0.0);
        assert!(cad_usd_latest.unwrap() > 0.0);
        assert!(twd_usd_latest.unwrap() > 0.0);
        assert!(btc_usd_2025.unwrap() > 0.0);
        assert!(eth_usd_2025.unwrap() > 0.0);
        assert!(cad_usd_2025.unwrap() > 0.0);
        assert!(twd_usd_2025.unwrap() > 0.0);
    }
}

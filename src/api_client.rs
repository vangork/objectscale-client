use anyhow::{bail, Context as _, Result};
use reqwest::blocking::{Client, ClientBuilder, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{de, Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Default)]
pub struct APIClient {
    client: Client,
    endpoint: String,
    username: String,
    password: String,

    access_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    refresh_expires_in: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthLoginResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenResponse  {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
    pub token_type: String,
}


#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseMetadata {
    pub request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Account {
    pub account_id: String,
    pub objscale: String,
    pub create_date: String,
    #[serde(deserialize_with = "deserialize_bool")]
    pub encryption_enabled: bool,
    #[serde(deserialize_with = "deserialize_bool")]
    pub account_disabled: bool,
    pub alias: String,
    pub description: String,
    #[serde(deserialize_with = "deserialize_bool")]
    pub protection_enabled: bool,
    pub tso_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateAccountResult {
    pub account: Account,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateAccountResponse {
    pub response_metadata: ResponseMetadata,
    pub create_account_result: CreateAccountResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteAccountResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DisableAccountResponse {
    pub response_metadata: ResponseMetadata,
}

impl APIClient {
    pub fn new(endpoint: &str, username: &str, password: &str, insecure: bool) -> Self {
        let timeout = Duration::new(5, 0);
        let client = ClientBuilder::new().timeout(timeout).danger_accept_invalid_certs(insecure).build().expect("build client");
        Self {
            client,
            endpoint: endpoint.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            ..Default::default()
        }
    }

    fn obtain_auth_token(&mut self) -> Result<()> {
        let params = BasicAuth {
            username: self.username.clone(),
            password: self.password.clone(),
        };
        let request_url = format!("{}/mgmt/auth/login", self.endpoint);
        let resp = self.client.post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&params)
            .send()?;

        let contents = get_success_contents(resp)?;
        let resp: AuthLoginResponse = serde_json::from_str(&contents).with_context(|| format!("Unable to deserialise AuthLoginResponse. Body was: \"{}\"", contents))?;
        let obtain_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.access_token = Some(resp.access_token);
        self.refresh_token = Some(resp.refresh_token);
        self.expires_in = Some(resp.expires_in + obtain_time);
        self.refresh_expires_in = Some(resp.refresh_expires_in + obtain_time);
        Ok(())
    }

    fn refresh_auth_token(&mut self) -> Result<()> {
        let request_url = format!("{}/mgmt/auth/token?grant_type=refresh_token&refresh_token={}", self.endpoint, self.refresh_token.clone().unwrap());
        let resp = self.client.post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .send()?;

        let contents = get_success_contents(resp)?;
        let resp: RefreshTokenResponse = serde_json::from_str(&contents).with_context(|| format!("Unable to deserialise RefreshTokenResponse. Body was: \"{}\"", contents))?;
        self.access_token = Some(resp.access_token);
        self.refresh_token = Some(resp.refresh_token);
        self.expires_in = Some(resp.expires_in);
        self.refresh_expires_in = Some(resp.refresh_expires_in);
        Ok(())
    }

    fn auth(&mut self) -> Result<()> {
        if self.access_token.is_none() {
            self.obtain_auth_token()?;
        } else {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if self.expires_in.unwrap() > now {
            } else {
                if self.refresh_expires_in.unwrap() > now {
                    self.refresh_auth_token()?;
                } else {
                    self.obtain_auth_token()?;
                }
            }
        }
        Ok(())
    }

    pub fn create_account(&mut self, alias: &str) -> Result<Account> {
        self.auth()?;
        let request_url = format!("{}/iam?Action=CreateAccount&Alias={}", self.endpoint, alias);
        let resp = self.client.post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, self.access_token.as_ref().unwrap())
            .send()?;
        let contents = get_success_contents(resp)?;
        let resp: CreateAccountResponse = serde_json::from_str(&contents).with_context(|| format!("Unable to deserialise CreateAccountResponse. Body was: \"{}\"", contents))?;
        Ok(resp.create_account_result.account)
    }

    pub fn disable_account(&mut self, account_id: &str) -> Result<()> {
        self.auth()?;
        let request_url = format!("{}/iam?Action=DisableAccount&AccountId={}", self.endpoint, account_id);
        let resp = self.client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, self.access_token.as_ref().unwrap())
            .send()?;
        let contents = get_success_contents(resp)?;
        let _: DisableAccountResponse = serde_json::from_str(&contents).with_context(|| format!("Unable to deserialise DisableAccountResponse. Body was: \"{}\"", contents))?;
        Ok(())
    }

    pub fn delete_account(&mut self, account_id: &str) -> Result<()> {
        self.auth()?;
        self.disable_account(account_id)?;
        let request_url = format!("{}/iam?Action=DeleteAccount&AccountId={}", self.endpoint, account_id);
        let resp = self.client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, self.access_token.as_ref().unwrap())
            .send()?;
        let contents = get_success_contents(resp)?;
        let _: DeleteAccountResponse = serde_json::from_str(&contents).with_context(|| format!("Unable to deserialise DeleteAccountResponse. Body was: \"{}\"", contents))?;
        Ok(())
    }
}

fn get_success_contents(reponse: Response) -> Result<String> {
    let status = reponse.status();
    let text = reponse.text()?;
    if status.is_client_error() || status.is_server_error() {
        bail!("Request failed due to: {}", text);
    }
    Ok(text)
}

fn deserialize_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = de::Deserialize::deserialize(deserializer)?;

    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(de::Error::unknown_variant(s, &["true", "false"])),
    }
}

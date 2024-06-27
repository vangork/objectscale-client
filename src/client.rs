//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

//! Applications should always use this ManagementClient to manage ObjectScale resources.
//!

use crate::iam::Account;
use crate::response::get_content_text;
use anyhow::{Context as _, Result};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// ManagementClient manages ObjectScale resources with the ObjectScale REST API calls.
/// It also gets and manages tokens for authentication.
///
/// # Examples
/// ```no_run
/// use objectscale_client::client::ManagementClient;
/// use objectscale_client::iam::AccountBuilder;
///
/// fn main() {
///     let endpoint = "https://192.168.1.1:443";
///     let username = "admin";
///     let password = "pass";
///     let insecure = false;
///     let account_alias = "test";
///     let mut client = ManagementClient::new(endpoint, username, password, insecure);
///     let account = AccountBuilder::default().alias(account_alias).build().expect("build account");
///     client.create_account(account).expect("create account");
/// }
/// ```
#[derive(Debug, Default)]
pub struct ManagementClient {
    pub(crate) http_client: Client,
    pub(crate) endpoint: String,
    username: String,
    password: String,

    pub(crate) access_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    refresh_expires_in: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
struct AuthLoginResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct RefreshTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
    pub token_type: String,
}

impl ManagementClient {
    ///
    /// Build a new ManagementClient.
    ///
    pub fn new(endpoint: &str, username: &str, password: &str, insecure: bool) -> Self {
        let timeout = Duration::new(5, 0);
        let http_client = ClientBuilder::new()
            .timeout(timeout)
            .danger_accept_invalid_certs(insecure)
            .use_rustls_tls()
            .build()
            .expect("build client");
        Self {
            http_client,
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
        let resp = self
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&params)
            .send()?;

        let text = get_content_text(resp)?;
        let resp: AuthLoginResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise AuthLoginResponse. Body was: \"{}\"",
                text
            )
        })?;
        let obtain_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.access_token = Some(resp.access_token);
        self.refresh_token = Some(resp.refresh_token);
        self.expires_in = Some(resp.expires_in + obtain_time);
        self.refresh_expires_in = Some(resp.refresh_expires_in + obtain_time);
        Ok(())
    }

    fn refresh_auth_token(&mut self) -> Result<()> {
        let request_url = format!(
            "{}/mgmt/auth/token?grant_type=refresh_token&refresh_token={}",
            self.endpoint,
            self.refresh_token.clone().unwrap()
        );
        let resp = self
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .send()?;

        let text = get_content_text(resp)?;
        let resp: RefreshTokenResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise RefreshTokenResponse. Body was: \"{}\"",
                text
            )
        })?;
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
            } else if self.refresh_expires_in.unwrap() > now {
                self.refresh_auth_token()?;
            } else {
                self.obtain_auth_token()?;
            }
        }
        Ok(())
    }

    ///
    /// Create an IAM account.
    ///
    pub fn create_account(&mut self, account: Account) -> Result<Account> {
        self.auth()?;
        if account.tags.is_empty() {
            Account::create_account(self, account)
        } else {
            let tags = account.tags.clone();
            let account = Account::create_account(self, account)?;
            Account::tag_account(self, account.account_id.as_str(), tags)?;
            Account::get_account(self, account.account_id.as_str())
        }
    }

    ///
    /// Get an IAM account.
    ///
    pub fn get_account(&mut self, account_id: &str) -> Result<Account> {
        self.auth()?;
        Account::get_account(self, account_id)
    }

    ///
    /// Delete an IAM account.
    ///
    pub fn delete_account(&mut self, account_id: &str) -> Result<()> {
        self.auth()?;
        let account = Account::get_account(self, account_id)?;
        if !account.account_disabled {
            Account::disable_account(self, account_id)?;
        }
        Account::delete_account(self, account_id)
    }

    ///
    /// List all IAM accounts.
    ///
    pub fn list_accounts(&mut self) -> Result<Vec<Account>> {
        self.auth()?;
        Account::list_accounts(self)
    }
}

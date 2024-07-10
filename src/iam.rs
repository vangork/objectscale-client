//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

//! Implements the API interface for identity and access management operations.
//!

use crate::client::ManagementClient;
use crate::response::get_content_text;
use anyhow::{anyhow, Context as _, Result};
use derive_builder::Builder;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::{deserialize_bool_from_anything, deserialize_default_from_null};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateAccountResult {
    pub account: Account,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ResponseMetadata {
    pub request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateAccountResponse {
    pub response_metadata: ResponseMetadata,
    pub create_account_result: CreateAccountResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TagAccountResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetAccountResult {
    pub account: Account,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetAccountResponse {
    pub response_metadata: ResponseMetadata,
    pub get_account_result: GetAccountResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteAccountResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DisableAccountResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAccountsResult {
    pub account_metadata: Vec<Account>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAccountsResponse {
    // Does not align with API description
    pub response_metadata: ResponseMetadata,
    pub list_accounts_result: ListAccountsResult,
}

/// Lables for IAM account, role and user.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Tag {
    /// tag key
    pub key: String,
    /// tag value
    pub value: String,
}

/// An ObjectScale Account is a logical construct that corresponds to a customer business unit, tenant, project, and so on.
///
/// You can build an Account with AccountBuilder and pass to [`create_account`](`ManagementClient::create_account`) method.
///  [`get_account`](`ManagementClient::get_account`) would fetch the existing Account from ObjectScale server.
///
/// # Examples
/// ```no_run
/// use objectscale_client::iam::{AccountBuilder, Tag};
/// let account = AccountBuilder::default()
///     .alias("test")
///     .encryption_enabled(true)
///     .description("test")
///     .tags(vec![Tag {
///         key: "key1".to_string(),
///         value: "value1".to_string(),
///     }])
///     .build()
///     .expect("account");
/// ```
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct Account {
    /// The Id of the account
    pub account_id: String,
    /// The name/id of the object scale that the account is associated with
    pub objscale: String,
    /// The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the account created
    pub create_date: String,
    /// Indicate if encryption is enabled for the account
    #[builder(setter(skip = false), default = "false")]
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub encryption_enabled: bool,
    /// account disabled
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub account_disabled: bool,
    #[builder(setter(into))]
    /// An Alias for an account
    pub alias: String,
    #[builder(setter(into), default)]
    /// The description for an account
    pub description: String,
    /// protection enabled
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub protection_enabled: bool,
    /// Tso id
    // list account API won't return tso_id
    #[serde(default)]
    pub tso_id: String,
    /// Labels
    // If tags are not set, it won't have the field of "Tags" in create/get account reponse
    #[builder(setter(skip = false), default)]
    #[serde(default, deserialize_with = "deserialize_default_from_null")]
    pub tags: Vec<Tag>,
}

impl Account {
    pub(crate) fn create_account(
        client: &mut ManagementClient,
        account: Account,
    ) -> Result<Account> {
        // EncryptionEnabled dose not align with api description
        // IsComplianceEnabled dose not work
        let request_url = format!(
            "{}/iam?Action=CreateAccount&Alias={}&EncryptionEnabled={}&Description={}",
            client.endpoint, account.alias, account.encryption_enabled, account.description,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let resp: CreateAccountResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise CreateAccountResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(resp.create_account_result.account)
    }

    pub(crate) fn tag_account(
        client: &mut ManagementClient,
        account_id: &str,
        tags: Vec<Tag>,
    ) -> Result<()> {
        if tags.is_empty() {
            return Ok(());
        }
        let mut request_url = format!(
            "{}/iam?Action=TagAccount&AccountId={}",
            client.endpoint, account_id,
        );
        for (index, tag) in tags.iter().enumerate() {
            request_url = format!(
                "{}&Tags.member.{}.Key={}&Tags.member.{}.Value={}",
                request_url,
                index + 1,
                tag.key,
                index + 1,
                tag.value
            );
        }

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let _: TagAccountResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise TagAccountResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn get_account(client: &mut ManagementClient, account_id: &str) -> Result<Account> {
        let request_url = format!(
            "{}/iam?Action=GetAccount&AccountId={}",
            client.endpoint, account_id,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let resp: GetAccountResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetAccountResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(resp.get_account_result.account)
    }

    pub(crate) fn disable_account(client: &mut ManagementClient, account_id: &str) -> Result<()> {
        let request_url = format!(
            "{}/iam?Action=DisableAccount&AccountId={}",
            client.endpoint, account_id
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let _: DisableAccountResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DisableAccountResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn delete_account(client: &mut ManagementClient, account_id: &str) -> Result<()> {
        let request_url = format!(
            "{}/iam?Action=DeleteAccount&AccountId={}",
            client.endpoint, account_id
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let _: DeleteAccountResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteAccountResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list_accounts(client: &mut ManagementClient) -> Result<Vec<Account>> {
        let mut accounts: Vec<Account> = vec![];
        let request_url = format!("{}/iam?Action=ListAccounts", client.endpoint);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListAccountsResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListAccountsResponse. Body was: \"{}\"",
                text
            )
        })?;
        accounts.extend(resp.list_accounts_result.account_metadata);
        while resp.list_accounts_result.is_truncated {
            let request_url = format!(
                "{}/iam?Action=ListAccounts?Marker={}",
                client.endpoint,
                resp.list_accounts_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAccountsResponse. Body was: \"{}\"",
                    text
                )
            })?;
            accounts.extend(resp.list_accounts_result.account_metadata);
        }
        Ok(accounts)
    }
}

use crate::client::ManagementClient;
use crate::response::{deserialize_bool, get_content_text};
use anyhow::{Context as _, Result};
use derive_builder::Builder;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateAccountResult {
    pub account: Account,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseMetadata {
    pub request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateAccountResponse {
    pub create_account_result: CreateAccountResult,
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TagAccountResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetAccountResult {
    pub account: Account,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetAccountResponse {
    pub get_account_result: GetAccountResult,
    pub response_metadata: ResponseMetadata,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Tag {
    pub key: String,
    pub value: String,
}

// AccountBuilder: alias, encryption_enabled, description, tags
#[derive(Builder, Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct Account {
    pub account_id: String,
    pub objscale: String,
    pub create_date: String,
    #[builder(setter(skip = false), default = "false")]
    #[serde(deserialize_with = "deserialize_bool")]
    pub encryption_enabled: bool,
    #[serde(deserialize_with = "deserialize_bool")]
    pub account_disabled: bool,
    #[builder(setter(into))]
    pub alias: String,
    #[builder(setter(into), default)]
    pub description: String,
    #[serde(deserialize_with = "deserialize_bool")]
    pub protection_enabled: bool,
    pub tso_id: String,
    // If tags are not set, it won't have the field of "Tags" in create/get account reponse
    #[builder(setter(skip = false), default)]
    #[serde(default)]
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
}

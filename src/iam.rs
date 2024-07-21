//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

//! Defines identity and access resources details.
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
struct UpdateAccountResult {
    pub account: Account,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UpdateAccountResponse {
    pub response_metadata: ResponseMetadata,
    pub update_account_result: UpdateAccountResult,
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
    // It does not have description field if to create account on GUI
    #[serde(default)]
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
            "{}iam?Action=CreateAccount&Alias={}&EncryptionEnabled={}&Description={}",
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
            "{}iam?Action=TagAccount&AccountId={}",
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
            "{}iam?Action=GetAccount&AccountId={}",
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

    pub(crate) fn update_account(
        client: &mut ManagementClient,
        account: Account,
    ) -> Result<Account> {
        let request_url = format!(
            "{}iam?Action=UpdateAccount&AccountId={}&Alias={}&Description={}",
            client.endpoint, account.account_id, account.alias, account.description,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let resp: UpdateAccountResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise UpdateAccountResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(resp.update_account_result.account)
    }

    pub(crate) fn disable_account(client: &mut ManagementClient, account_id: &str) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DisableAccount&AccountId={}",
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
            "{}iam?Action=DeleteAccount&AccountId={}",
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
        let request_url = format!("{}iam?Action=ListAccounts", client.endpoint);
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
        let mut accounts: Vec<Account> = vec![];
        accounts.extend(resp.list_accounts_result.account_metadata);
        while resp.list_accounts_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListAccounts?Marker={}",
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

/// In ObjectScale, an IAM User is a person or application in the account.
// TODO:
// - Support for `inline_policy` for user, group and role
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct User {
    /// Arn that identifies the user.
    pub arn: String,
    /// ISO 8601 format DateTime when user was created.
    // serde(default) is for GetGroupResponse which doesn't contain create_date
    #[serde(default)]
    pub create_date: String,
    /// The path to the IAM User.
    pub path: String,
    /// Permissions boundary
    // list users API won't return permissions_boundary
    #[builder(setter(skip = false), default)]
    #[serde(default)]
    pub permissions_boundary: PermissionsBoundary,
    /// Unique Id associated with the User.
    pub user_id: String,
    /// Simple name identifying the User.
    #[builder(setter(into))]
    pub user_name: String,
    /// The list of Tags associated with the User.
    #[builder(setter(skip = false), default)]
    #[serde(default, deserialize_with = "deserialize_default_from_null")]
    pub tags: Vec<Tag>,
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PermissionsBoundary {
    /// The ARN of the policy set as permissions boundary.
    pub permissions_boundary_arn: String,
    /// The permissions boundary usage type that indicates what type of IAM resource is used as the permissions boundary for an entity. This data type can only have a value of Policy.
    pub permissions_boundary_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateUserResult {
    pub user: User,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateUserResponse {
    pub response_metadata: ResponseMetadata,
    pub create_user_result: CreateUserResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TagUserResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetUserResult {
    pub user: User,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetUserResponse {
    pub response_metadata: ResponseMetadata,
    pub get_user_result: GetUserResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteUserResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListUsersResult {
    pub users: Vec<User>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListUsersResponse {
    pub response_metadata: ResponseMetadata,
    pub list_users_result: ListUsersResult,
}

impl User {
    pub(crate) fn create(client: &mut ManagementClient, user: User) -> Result<User> {
        let request_url = format!(
            "{}iam?Action=CreateUser&UserName={}",
            client.endpoint, user.user_name,
        );
        let namespace = user.namespace;
        let mut req = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace);

        if !user
            .permissions_boundary
            .permissions_boundary_arn
            .is_empty()
        {
            req = req.query(&[(
                "PermissionsBoundary",
                user.permissions_boundary.permissions_boundary_arn,
            )]);
        }
        for (index, tag) in user.tags.iter().enumerate() {
            req = req.query(&[(&format!("Tags.member.{}.Key", index + 1), &tag.key)]);
            req = req.query(&[(&format!("Tags.member.{}.Value", index + 1), &tag.value)]);
        }

        let resp = req.send()?;
        let text = get_content_text(resp)?;
        let resp: CreateUserResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise CreateUserResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut user = resp.create_user_result.user;
        user.namespace = namespace;
        Ok(user)
    }

    pub(crate) fn tag_user(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
        tags: Vec<Tag>,
    ) -> Result<()> {
        if tags.is_empty() {
            return Ok(());
        }
        let mut request_url = format!(
            "{}iam?Action=TagUser&UserName={}",
            client.endpoint, user_name,
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
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: TagUserResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise TagUserResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn get(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
    ) -> Result<User> {
        let request_url = format!(
            "{}iam?Action=GetUser&UserName={}",
            client.endpoint, user_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let resp: GetUserResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetUserResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut user = resp.get_user_result.user;
        user.namespace = namespace.to_string();
        Ok(user)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteUser&UserName={}",
            client.endpoint, user_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: DeleteUserResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteUserResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(client: &mut ManagementClient, namespace: &str) -> Result<Vec<User>> {
        let request_url = format!("{}iam?Action=ListUsers", client.endpoint);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListUsersResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListUsersResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut users: Vec<User> = vec![];
        users.extend(resp.list_users_result.users);
        while resp.list_users_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListUsers&Marker={}",
                client.endpoint,
                resp.list_users_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListUsersResponse. Body was: \"{}\"",
                    text
                )
            })?;
            users.extend(resp.list_users_result.users);
        }
        users
            .iter_mut()
            .for_each(|user| user.namespace = namespace.to_string());
        Ok(users)
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct UserPolicyAttachment {
    #[builder(setter(into))]
    #[serde(default)]
    pub user_name: String,
    pub policy_name: String,
    #[builder(setter(into))]
    pub policy_arn: String,
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AttachUserPolicyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DetachUserPolicyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAttachedUserPoliciesResult {
    pub attached_policies: Vec<UserPolicyAttachment>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAttachedUserPoliciesResponse {
    pub response_metadata: ResponseMetadata,
    pub list_attached_user_policies_result: ListAttachedUserPoliciesResult,
}

impl UserPolicyAttachment {
    pub(crate) fn create(
        client: &mut ManagementClient,
        user_policy_attachment: UserPolicyAttachment,
    ) -> Result<UserPolicyAttachment> {
        let request_url = format!(
            "{}iam?Action=AttachUserPolicy&UserName={}&PolicyArn={}",
            client.endpoint, user_policy_attachment.user_name, user_policy_attachment.policy_arn,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &user_policy_attachment.namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: AttachUserPolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise AttachUserPolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(user_policy_attachment)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        user_policy_attachment: UserPolicyAttachment,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DetachUserPolicy&UserName={}&PolicyArn={}",
            client.endpoint, user_policy_attachment.user_name, user_policy_attachment.policy_arn,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", user_policy_attachment.namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: DetachUserPolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DetachUserPolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
    ) -> Result<Vec<UserPolicyAttachment>> {
        let request_url = format!(
            "{}iam?Action=ListAttachedUserPolicies&UserName={}",
            client.endpoint, user_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListAttachedUserPoliciesResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAttachedUserPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut attachments: Vec<UserPolicyAttachment> = vec![];
        attachments.extend(resp.list_attached_user_policies_result.attached_policies);
        while resp.list_attached_user_policies_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListAttachedUserPolicies&UserName={}&Marker={}",
                client.endpoint,
                user_name,
                resp.list_attached_user_policies_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAttachedUserPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
            attachments.extend(resp.list_attached_user_policies_result.attached_policies);
        }
        attachments.iter_mut().for_each(|attachment| {
            attachment.namespace = namespace.to_string();
            attachment.user_name = user_name.to_string();
        });
        Ok(attachments)
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct LoginProfile {
    pub create_date: String,
    #[builder(setter(into))]
    pub user_name: String,
    #[builder(setter(skip = false), default)]
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub password_reset_required: bool,
    #[builder(setter(into))]
    #[serde(default)]
    pub password: String,
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateLoginProfileResult {
    pub login_profile: LoginProfile,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateLoginProfileResponse {
    pub response_metadata: ResponseMetadata,
    pub create_login_profile_result: CreateLoginProfileResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetLoginProfileResult {
    pub login_profile: LoginProfile,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetLoginProfileResponse {
    pub response_metadata: ResponseMetadata,
    pub get_login_profile_result: GetLoginProfileResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteLoginProfileResponse {
    pub response_metadata: ResponseMetadata,
}

impl LoginProfile {
    pub(crate) fn create(
        client: &mut ManagementClient,
        login_profile: LoginProfile,
    ) -> Result<LoginProfile> {
        let request_url = format!(
            "{}iam?Action=CreateLoginProfile&UserName={}&Password={}&PasswordResetRequired={}",
            client.endpoint,
            login_profile.user_name,
            login_profile.password,
            login_profile.password_reset_required,
        );

        let namespace = login_profile.namespace;
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let resp: CreateLoginProfileResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise CreateLoginProfileResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut login_profile = resp.create_login_profile_result.login_profile;
        login_profile.namespace = namespace;
        Ok(login_profile)
    }

    pub(crate) fn get(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
    ) -> Result<LoginProfile> {
        let request_url = format!(
            "{}iam?Action=GetLoginProfile&UserName={}",
            client.endpoint, user_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let resp: GetLoginProfileResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetLoginProfileResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut login_profile = resp.get_login_profile_result.login_profile;
        login_profile.namespace = namespace.to_string();
        Ok(login_profile)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteLoginProfile&UserName={}",
            client.endpoint, user_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: DeleteLoginProfileResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteLoginProfileResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }
}

/// IAM User access key
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct AccessKey {
    /// The Id of this access key
    pub access_key_id: String,
    /// The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the access key was created.
    pub create_date: String,
    /// The secret key
    #[serde(default)]
    pub secret_access_key: String,
    /// The status of the access key {Active | Inactive}
    pub status: String,
    /// The name of the user that the access key is associated with.
    #[builder(setter(into))]
    pub user_name: String,
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateAccessKeyResult {
    pub access_key: AccessKey,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateAccessKeyResponse {
    pub response_metadata: ResponseMetadata,
    pub create_access_key_result: CreateAccessKeyResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UpdateAccessKeyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteAccessKeyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAccessKeysResult {
    pub access_key_metadata: Vec<AccessKey>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAccessKeysResponse {
    pub response_metadata: ResponseMetadata,
    pub list_access_keys_result: ListAccessKeysResult,
}

impl AccessKey {
    pub(crate) fn create(
        client: &mut ManagementClient,
        access_key: AccessKey,
    ) -> Result<AccessKey> {
        let request_url = format!(
            "{}iam?Action=CreateAccessKey&UserName={}",
            client.endpoint, access_key.user_name,
        );
        let namespace = access_key.namespace;
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let resp: CreateAccessKeyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise CreateAccessKeyResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut access_key = resp.create_access_key_result.access_key;
        access_key.namespace = namespace;
        Ok(access_key)
    }

    pub(crate) fn update(client: &mut ManagementClient, access_key: AccessKey) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=UpdateAccessKey&UserName={}&AccessKeyId={}&Status={}",
            client.endpoint, access_key.user_name, access_key.access_key_id, access_key.status
        );
        let namespace = access_key.namespace;
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: UpdateAccessKeyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise UpdateAccessKeyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        access_key_id: &str,
        user_name: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteAccessKey&UserName={}&AccessKeyId={}",
            client.endpoint, user_name, access_key_id,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: DeleteAccessKeyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteAccessKeyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
    ) -> Result<Vec<AccessKey>> {
        let request_url = format!(
            "{}iam?Action=ListAccessKeys&UserName={}",
            client.endpoint, user_name
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListAccessKeysResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListAccessKeysResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut access_keys: Vec<AccessKey> = vec![];
        access_keys.extend(resp.list_access_keys_result.access_key_metadata);
        while resp.list_access_keys_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListAccessKeys&UserName={}&Marker={}",
                client.endpoint,
                user_name,
                resp.list_access_keys_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAccessKeysResponse. Body was: \"{}\"",
                    text
                )
            })?;
            access_keys.extend(resp.list_access_keys_result.access_key_metadata);
        }
        access_keys
            .iter_mut()
            .for_each(|access_key| access_key.namespace = namespace.to_string());
        Ok(access_keys)
    }
}

/// IAM Account access key
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct AccountAccessKey {
    /// The Id of this access key
    pub access_key_id: String,
    /// The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the access key was created.
    pub create_date: String,
    /// The secret key
    #[serde(default)]
    pub secret_access_key: String,
    /// The status of the access key {Active | Inactive}
    pub status: String,
    /// The name of the user that the access key is associated with.
    #[builder(setter(into))]
    pub account_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateAccountAccessKeyResult {
    pub access_key: AccountAccessKey,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateAccountAccessKeyResponse {
    pub response_metadata: ResponseMetadata,
    pub create_account_access_key_result: CreateAccountAccessKeyResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UpdateAccountAccessKeyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteAccountAccessKeyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAccountAccessKeysResult {
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub access_key_metadata: Vec<AccountAccessKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAccountAccessKeysResponse {
    pub response_metadata: ResponseMetadata,
    pub list_account_access_keys_result: ListAccountAccessKeysResult,
}

impl AccountAccessKey {
    pub(crate) fn create(
        client: &mut ManagementClient,
        account_access_key: AccountAccessKey,
    ) -> Result<AccountAccessKey> {
        let request_url = format!(
            "{}iam?Action=CreateAccountAccessKey&AccountId={}",
            client.endpoint, account_access_key.account_id,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let resp: CreateAccountAccessKeyResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise CreateAccountAccessKeyResponse. Body was: \"{}\"",
                    text
                )
            })?;
        Ok(resp.create_account_access_key_result.access_key)
    }

    pub(crate) fn update(
        client: &mut ManagementClient,
        account_access_key: AccountAccessKey,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=UpdateAccountAccessKey&AccountId={}&AccessKeyId={}&Status={}",
            client.endpoint,
            account_access_key.account_id,
            account_access_key.access_key_id,
            account_access_key.status
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let _: UpdateAccountAccessKeyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise UpdateAccountAccessKeyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        access_key_id: &str,
        account_id: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteAccountAccessKey&AccessKeyId={}&AccountId={}",
            client.endpoint, access_key_id, account_id,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let _: DeleteAccountAccessKeyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteAccountAccessKeyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(
        client: &mut ManagementClient,
        account_id: &str,
    ) -> Result<Vec<AccountAccessKey>> {
        let request_url = format!(
            "{}iam?Action=ListAccountAccessKeys&AccountId={}",
            client.endpoint, account_id
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp)?;
        let resp: ListAccountAccessKeysResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAccountAccessKeysResponse. Body was: \"{}\"",
                    text
                )
            })?;

        Ok(resp.list_account_access_keys_result.access_key_metadata)
    }
}

/// IAM policies are documents in JSON format that define permissions for an operation regardless of the method that you use to perform the operation.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct Policy {
    /// The resource name of the policy.
    pub arn: String,
    /// The number of entities (users, groups, and roles) that the policy is attached to.
    pub attachment_count: i64,
    /// The date and time, in ISO 8601 date-time format, when the policy was created.
    pub create_date: String,
    /// The identifier for the version of the policy that is set as the default version.
    pub default_version_id: String,
    /// A friendly description of the policy.
    #[builder(setter(into), default)]
    pub description: String,
    /// Specifies whether the policy can be attached to user, group, or role.
    pub is_attachable: bool,
    /// The path to the policy
    pub path: String,
    /// Resource name of the policy that is used to set permissions boundary for the policy.
    pub permissions_boundary_usage_count: i64,
    /// The stable and unique string identifying the policy.
    pub policy_id: String,
    /// The friendly name of the policy.
    #[builder(setter(into))]
    pub policy_name: String,
    /// The date and time, in ISO 8601 date-time format, when the policy was created.
    pub update_date: String,
    #[builder(setter(into))]
    #[serde(default)]
    pub policy_document: String,
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreatePolicyResult {
    pub policy: Policy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreatePolicyResponse {
    pub response_metadata: ResponseMetadata,
    pub create_policy_result: CreatePolicyResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetPolicyResult {
    pub policy: Policy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetPolicyResponse {
    pub response_metadata: ResponseMetadata,
    pub get_policy_result: GetPolicyResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeletePolicyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListPoliciesResult {
    pub policies: Vec<Policy>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListPoliciesResponse {
    pub response_metadata: ResponseMetadata,
    pub list_policies_result: ListPoliciesResult,
}

impl Policy {
    pub(crate) fn create(client: &mut ManagementClient, policy: Policy) -> Result<Policy> {
        let request_url = format!(
            "{}iam?Action=CreatePolicy&PolicyName={}&PolicyDocument={}&Description={}",
            client.endpoint, policy.policy_name, policy.policy_document, policy.description,
        );
        let namespace = policy.namespace;
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let resp: CreatePolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise CreatePolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut policy = resp.create_policy_result.policy;
        policy.namespace = namespace;
        Ok(policy)
    }

    pub(crate) fn get(
        client: &mut ManagementClient,
        policy_arn: &str,
        namespace: &str,
    ) -> Result<Policy> {
        let request_url = format!(
            "{}iam?Action=GetPolicy&PolicyArn={}",
            client.endpoint, policy_arn,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let resp: GetPolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetPolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut policy = resp.get_policy_result.policy;
        policy.namespace = namespace.to_string();
        Ok(policy)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        policy_arn: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeletePolicy&PolicyArn={}",
            client.endpoint, policy_arn,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: DeletePolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeletePolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(client: &mut ManagementClient, namespace: &str) -> Result<Vec<Policy>> {
        let request_url = format!("{}iam?Action=ListPolicies", client.endpoint);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListPoliciesResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListPoliciesResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut policies: Vec<Policy> = vec![];
        policies.extend(resp.list_policies_result.policies);
        while resp.list_policies_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListPolicies&Marker={}",
                client.endpoint,
                resp.list_policies_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
            policies.extend(resp.list_policies_result.policies);
        }
        policies
            .iter_mut()
            .for_each(|policy| policy.namespace = namespace.to_string());
        Ok(policies)
    }
}

/// A Group is a collection of Users. You can use groups to specify permissions for a collection of users.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct Group {
    /// Arn that identifies the Group.
    pub arn: String,
    /// ISO 8601 format DateTime when group was created.
    // serde(default) is for ListGroupsForUserResponse which doesn't contain create_date
    #[serde(default)]
    pub create_date: String,
    /// The path to the IAM Group.
    pub path: String,
    /// Unique Id associated with the Group.
    pub group_id: String,
    /// Simple name identifying the Group.
    #[builder(setter(into))]
    pub group_name: String,
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateGroupResult {
    pub group: Group,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateGroupResponse {
    pub response_metadata: ResponseMetadata,
    pub create_group_result: CreateGroupResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetGroupResult {
    pub group: Group,
    pub users: Vec<User>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetGroupResponse {
    pub response_metadata: ResponseMetadata,
    pub get_group_result: GetGroupResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteGroupResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListGroupsResult {
    pub groups: Vec<Group>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListGroupsResponse {
    pub response_metadata: ResponseMetadata,
    pub list_groups_result: ListGroupsResult,
}

impl Group {
    pub(crate) fn create(client: &mut ManagementClient, group: Group) -> Result<Group> {
        let request_url = format!(
            "{}iam?Action=CreateGroup&GroupName={}",
            client.endpoint, group.group_name,
        );
        let namespace = group.namespace;
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let resp: CreateGroupResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise CreateGroupResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut group = resp.create_group_result.group;
        group.namespace = namespace;
        Ok(group)
    }

    pub(crate) fn get(
        client: &mut ManagementClient,
        group_name: &str,
        namespace: &str,
    ) -> Result<Group> {
        let request_url = format!(
            "{}iam?Action=GetGroup&GroupName={}",
            client.endpoint, group_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let resp: GetGroupResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetGroupResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut group = resp.get_group_result.group;
        group.namespace = namespace.to_string();
        Ok(group)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        group_name: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteGroup&GroupName={}",
            client.endpoint, group_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: DeleteGroupResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteGroupResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(client: &mut ManagementClient, namespace: &str) -> Result<Vec<Group>> {
        let request_url = format!("{}iam?Action=ListGroups", client.endpoint);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListGroupsResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListGroupsResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut groups: Vec<Group> = vec![];
        groups.extend(resp.list_groups_result.groups);
        while resp.list_groups_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListGroups&Marker={}",
                client.endpoint,
                resp.list_groups_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListGroupsResponse. Body was: \"{}\"",
                    text
                )
            })?;
            groups.extend(resp.list_groups_result.groups);
        }
        groups
            .iter_mut()
            .for_each(|group| group.namespace = namespace.to_string());
        Ok(groups)
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct GroupPolicyAttachment {
    #[builder(setter(into))]
    #[serde(default)]
    pub group_name: String,
    pub policy_name: String,
    #[builder(setter(into))]
    pub policy_arn: String,
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AttachGroupPolicyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DetachGroupPolicyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAttachedGroupPoliciesResult {
    pub attached_policies: Vec<GroupPolicyAttachment>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAttachedGroupPoliciesResponse {
    pub response_metadata: ResponseMetadata,
    pub list_attached_group_policies_result: ListAttachedGroupPoliciesResult,
}

impl GroupPolicyAttachment {
    pub(crate) fn create(
        client: &mut ManagementClient,
        group_policy_attachment: GroupPolicyAttachment,
    ) -> Result<GroupPolicyAttachment> {
        let request_url = format!(
            "{}iam?Action=AttachGroupPolicy&GroupName={}&PolicyArn={}",
            client.endpoint, group_policy_attachment.group_name, group_policy_attachment.policy_arn,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &group_policy_attachment.namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: AttachGroupPolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise AttachGroupPolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(group_policy_attachment)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        group_policy_attachment: GroupPolicyAttachment,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DetachGroupPolicy&GroupName={}&PolicyArn={}",
            client.endpoint, group_policy_attachment.group_name, group_policy_attachment.policy_arn,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", group_policy_attachment.namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: DetachGroupPolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DetachGroupPolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(
        client: &mut ManagementClient,
        group_name: &str,
        namespace: &str,
    ) -> Result<Vec<GroupPolicyAttachment>> {
        let request_url = format!(
            "{}iam?Action=ListAttachedGroupPolicies&GroupName={}",
            client.endpoint, group_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListAttachedGroupPoliciesResponse = serde_json::from_str(&text)
            .with_context(|| {
                format!(
                    "Unable to deserialise ListAttachedGroupPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut attachments: Vec<GroupPolicyAttachment> = vec![];
        attachments.extend(resp.list_attached_group_policies_result.attached_policies);
        while resp.list_attached_group_policies_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListAttachedGroupPolicies&GroupName={}&Marker={}",
                client.endpoint,
                group_name,
                resp.list_attached_group_policies_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAttachedGroupPolicies. Body was: \"{}\"",
                    text
                )
            })?;
            attachments.extend(resp.list_attached_group_policies_result.attached_policies);
        }
        attachments.iter_mut().for_each(|attachment| {
            attachment.namespace = namespace.to_string();
            attachment.group_name = group_name.to_string();
        });
        Ok(attachments)
    }
}

/// A role is similar to a user, in that it is an identity with permission policies that determine what the identity can and cannot do.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct Role {
    /// Arn that identifies the role.
    pub arn: String,
    /// The trust relationship policy document that grants an entity permission to assume the role.
    #[builder(setter(into))]
    pub assume_role_policy_document: String,
    /// ISO 8601 DateTime when role was created.
    pub create_date: String,
    /// The description of the IAM role.
    #[builder(setter(into), default)]
    pub description: String,
    /// The maximum session duration (in seconds) that you want to set for the specified role.
    #[builder(setter(skip = false), default)]
    pub max_session_duration: i32,
    /// The path to the IAM role.
    pub path: String,
    /// Unique Id associated with the role.
    pub role_id: String,
    /// Simple name identifying the role.
    #[builder(setter(into))]
    pub role_name: String,
    /// The list of Tags associated with the role.
    #[builder(setter(skip = false), default)]
    #[serde(default, deserialize_with = "deserialize_default_from_null")]
    pub tags: Vec<Tag>,
    /// Permissions boundary
    // list role API won't return permissions_boundary if not set
    #[builder(setter(skip = false), default)]
    #[serde(default)]
    pub permissions_boundary: PermissionsBoundary,
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateRoleResult {
    pub role: Role,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateRoleResponse {
    pub response_metadata: ResponseMetadata,
    pub create_role_result: CreateRoleResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetRoleResult {
    pub role: Role,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetRoleResponse {
    pub response_metadata: ResponseMetadata,
    pub get_role_result: GetRoleResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UpdateRoleResult {
    pub role: Role,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UpdateRoleResponse {
    pub response_metadata: ResponseMetadata,
    pub update_role_result: UpdateRoleResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteRoleResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListRolesResult {
    pub roles: Vec<Role>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListRolesResponse {
    pub response_metadata: ResponseMetadata,
    pub list_roles_result: ListRolesResult,
}

impl Role {
    pub(crate) fn create(client: &mut ManagementClient, role: Role) -> Result<Role> {
        let request_url = format!(
            "{}iam?Action=CreateRole&RoleName={}&AssumeRolePolicyDocument={}",
            client.endpoint, role.role_name, role.assume_role_policy_document,
        );
        let namespace = role.namespace;
        let mut req = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace);

        if !role.description.is_empty() {
            req = req.query(&[("Description", role.description)]);
        }
        if role.max_session_duration > 0 {
            req = req.query(&[("MaxSessionDuration", role.max_session_duration)]);
        }
        if !role
            .permissions_boundary
            .permissions_boundary_arn
            .is_empty()
        {
            req = req.query(&[(
                "PermissionsBoundary",
                role.permissions_boundary.permissions_boundary_arn,
            )]);
        }
        for (index, tag) in role.tags.iter().enumerate() {
            req = req.query(&[(&format!("Tags.member.{}.Key", index + 1), &tag.key)]);
            req = req.query(&[(&format!("Tags.member.{}.Value", index + 1), &tag.value)]);
        }
        let resp = req.send()?;
        let text = get_content_text(resp)?;
        let resp: CreateRoleResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise CreateRoleResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut role = resp.create_role_result.role;
        role.namespace = namespace;
        Ok(role)
    }

    pub(crate) fn get(
        client: &mut ManagementClient,
        role_name: &str,
        namespace: &str,
    ) -> Result<Role> {
        let request_url = format!(
            "{}iam?Action=GetRole&RoleName={}",
            client.endpoint, role_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let resp: GetRoleResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetRoleResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut role = resp.get_role_result.role;
        role.namespace = namespace.to_string();
        Ok(role)
    }

    pub(crate) fn update(client: &mut ManagementClient, role: Role) -> Result<Role> {
        let request_url = format!(
            "{}iam?Action=UpdateRole&RoleName={}",
            client.endpoint, role.role_name,
        );
        let namespace = role.namespace;
        let mut req = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace);

        if !role.description.is_empty() {
            req = req.query(&[("Description", role.description)]);
        }
        if role.max_session_duration > 0 {
            req = req.query(&[("MaxSessionDuration", role.max_session_duration)]);
        }

        let resp = req.send()?;
        let text = get_content_text(resp)?;
        let resp: UpdateRoleResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise UpdateRoleResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut role = resp.update_role_result.role;
        role.namespace = namespace;
        Ok(role)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        role_name: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteRole&RoleName={}",
            client.endpoint, role_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: DeleteRoleResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteRoleResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(client: &mut ManagementClient, namespace: &str) -> Result<Vec<Role>> {
        let request_url = format!("{}iam?Action=ListRoles", client.endpoint);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListRolesResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListRolesResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut roles: Vec<Role> = vec![];
        roles.extend(resp.list_roles_result.roles);
        while resp.list_roles_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListRoles&Marker={}",
                client.endpoint,
                resp.list_roles_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListRolesResponse. Body was: \"{}\"",
                    text
                )
            })?;
            roles.extend(resp.list_roles_result.roles);
        }
        roles
            .iter_mut()
            .for_each(|role| role.namespace = namespace.to_string());
        Ok(roles)
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct RolePolicyAttachment {
    #[builder(setter(into))]
    #[serde(default)]
    pub role_name: String,
    pub policy_name: String,
    #[builder(setter(into))]
    pub policy_arn: String,
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AttachRolePolicyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DetachRolePolicyResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAttachedRolePoliciesResult {
    pub attached_policies: Vec<RolePolicyAttachment>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListAttachedRolePoliciesResponse {
    pub response_metadata: ResponseMetadata,
    pub list_attached_role_policies_result: ListAttachedRolePoliciesResult,
}

impl RolePolicyAttachment {
    pub(crate) fn create(
        client: &mut ManagementClient,
        role_policy_attachment: RolePolicyAttachment,
    ) -> Result<RolePolicyAttachment> {
        let request_url = format!(
            "{}iam?Action=AttachRolePolicy&RoleName={}&PolicyArn={}",
            client.endpoint, role_policy_attachment.role_name, role_policy_attachment.policy_arn,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &role_policy_attachment.namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: AttachRolePolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise AttachRolePolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(role_policy_attachment)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        role_policy_attachment: RolePolicyAttachment,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DetachRolePolicy&RoleName={}&PolicyArn={}",
            client.endpoint, role_policy_attachment.role_name, role_policy_attachment.policy_arn,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", role_policy_attachment.namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: DetachRolePolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DetachRolePolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(
        client: &mut ManagementClient,
        role_name: &str,
        namespace: &str,
    ) -> Result<Vec<RolePolicyAttachment>> {
        let request_url = format!(
            "{}iam?Action=ListAttachedRolePolicies&RoleName={}",
            client.endpoint, role_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListAttachedRolePoliciesResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAttachedRolePoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut attachments: Vec<RolePolicyAttachment> = vec![];
        attachments.extend(resp.list_attached_role_policies_result.attached_policies);
        while resp.list_attached_role_policies_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListAttachedRolePolicies&RoleName={}&Marker={}",
                client.endpoint,
                role_name,
                resp.list_attached_role_policies_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAttachedRolePolicies. Body was: \"{}\"",
                    text
                )
            })?;
            attachments.extend(resp.list_attached_role_policies_result.attached_policies);
        }
        attachments.iter_mut().for_each(|attachment| {
            attachment.namespace = namespace.to_string();
            attachment.role_name = role_name.to_string();
        });
        Ok(attachments)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct EntitiesForPolicy {
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PolicyUser {
    pub user_name: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PolicyGroup {
    pub group_name: String,
    pub group_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PolicyRole {
    pub role_name: String,
    pub role_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListEntitiesForPolicyResult {
    pub policy_users: Vec<PolicyUser>,
    pub policy_groups: Vec<PolicyGroup>,
    pub policy_roles: Vec<PolicyRole>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListEntitiesForPolicyResponse {
    pub response_metadata: ResponseMetadata,
    pub list_entities_for_policy_result: ListEntitiesForPolicyResult,
}

impl EntitiesForPolicy {
    pub(crate) fn get(
        client: &mut ManagementClient,
        policy_arn: &str,
        namespace: &str,
        entity_filter: &str,
        usage_filter: &str,
    ) -> Result<EntitiesForPolicy> {
        let mut request_url = format!(
            "{}iam?Action=ListEntitiesForPolicy&PolicyArn={}",
            client.endpoint, policy_arn,
        );
        if !entity_filter.is_empty() {
            request_url = format!("{}&EntityFilter={}", request_url, entity_filter);
        }
        if !usage_filter.is_empty() {
            request_url = format!("{}&PolicyUsageFilter={}", request_url, usage_filter);
        }
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListEntitiesForPolicyResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListEntitiesForPolicyResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut attachment = EntitiesForPolicy {
            users: vec![],
            groups: vec![],
            roles: vec![],
        };
        attachment.users.extend(
            resp.list_entities_for_policy_result
                .policy_users
                .into_iter()
                .map(|u| u.user_name)
                .collect::<Vec<String>>(),
        );
        attachment.groups.extend(
            resp.list_entities_for_policy_result
                .policy_groups
                .into_iter()
                .map(|u| u.group_name)
                .collect::<Vec<String>>(),
        );
        attachment.roles.extend(
            resp.list_entities_for_policy_result
                .policy_roles
                .into_iter()
                .map(|u| u.role_name)
                .collect::<Vec<String>>(),
        );
        while resp.list_entities_for_policy_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListEntitiesForPolicy&PolicyArn={}&PolicyUsageFilter={}&Marker={}",
                client.endpoint,
                policy_arn,
                entity_filter,
                resp.list_entities_for_policy_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListEntitiesForPolicyResponse. Body was: \"{}\"",
                    text
                )
            })?;
            attachment.users.extend(
                resp.list_entities_for_policy_result
                    .policy_users
                    .into_iter()
                    .map(|u| u.user_name)
                    .collect::<Vec<String>>(),
            );
            attachment.groups.extend(
                resp.list_entities_for_policy_result
                    .policy_groups
                    .into_iter()
                    .map(|u| u.group_name)
                    .collect::<Vec<String>>(),
            );
            attachment.roles.extend(
                resp.list_entities_for_policy_result
                    .policy_roles
                    .into_iter()
                    .map(|u| u.role_name)
                    .collect::<Vec<String>>(),
            );
        }
        Ok(attachment)
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct UserGroupMembership {
    #[builder(setter(into))]
    pub user_name: String,
    #[builder(setter(into))]
    pub group_name: String,
    #[builder(setter(into))]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AddUserToGroupResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RemoveUserFromGroupResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListGroupsForUserResult {
    pub groups: Vec<Group>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListGroupsForUserResponse {
    pub response_metadata: ResponseMetadata,
    pub list_groups_for_user_result: ListGroupsForUserResult,
}

impl UserGroupMembership {
    pub(crate) fn create(
        client: &mut ManagementClient,
        user_group_membership: UserGroupMembership,
    ) -> Result<UserGroupMembership> {
        let request_url = format!(
            "{}iam?Action=AddUserToGroup&UserName={}&GroupName={}",
            client.endpoint, user_group_membership.user_name, user_group_membership.group_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &user_group_membership.namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: AddUserToGroupResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise AttachUserPolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(user_group_membership)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        user_group_membership: UserGroupMembership,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=RemoveUserFromGroup&UserName={}&GroupName={}",
            client.endpoint, user_group_membership.user_name, user_group_membership.group_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", user_group_membership.namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let _: RemoveUserFromGroupResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise RemoveUserFromGroupResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list_by_user(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
    ) -> Result<Vec<UserGroupMembership>> {
        let request_url = format!(
            "{}iam?Action=ListGroupsForUser&UserName={}",
            client.endpoint, user_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: ListGroupsForUserResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListGroupsForUserResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut memberships: Vec<UserGroupMembership> = vec![];
        memberships.extend(
            resp.list_groups_for_user_result
                .groups
                .into_iter()
                .map(|u| UserGroupMembership {
                    user_name: user_name.to_string(),
                    group_name: u.group_name,
                    namespace: namespace.to_string(),
                })
                .collect::<Vec<UserGroupMembership>>(),
        );
        while resp.list_groups_for_user_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=ListGroupsForUser&UserName={}&Marker={}",
                client.endpoint,
                user_name,
                resp.list_groups_for_user_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListGroupsForUserResponse. Body was: \"{}\"",
                    text
                )
            })?;
            memberships.extend(
                resp.list_groups_for_user_result
                    .groups
                    .into_iter()
                    .map(|u| UserGroupMembership {
                        user_name: user_name.to_string(),
                        group_name: u.group_name,
                        namespace: namespace.to_string(),
                    })
                    .collect::<Vec<UserGroupMembership>>(),
            );
        }
        Ok(memberships)
    }

    pub(crate) fn list_by_group(
        client: &mut ManagementClient,
        group_name: &str,
        namespace: &str,
    ) -> Result<Vec<UserGroupMembership>> {
        let request_url = format!(
            "{}iam?Action=GetGroup&GroupName={}",
            client.endpoint, group_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)?;
        let mut resp: GetGroupResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetGroupResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut memberships: Vec<UserGroupMembership> = vec![];
        memberships.extend(
            resp.get_group_result
                .users
                .into_iter()
                .map(|u| UserGroupMembership {
                    user_name: u.user_name,
                    group_name: group_name.to_string(),
                    namespace: namespace.to_string(),
                })
                .collect::<Vec<UserGroupMembership>>(),
        );

        while resp.get_group_result.is_truncated {
            let request_url = format!(
                "{}iam?Action=GetGroup&GroupName={}&Marker={}",
                client.endpoint,
                group_name,
                resp.get_group_result
                    .marker
                    .ok_or_else(|| anyhow!("No marker found"))?,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTHORIZATION, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise GetGroupResponse. Body was: \"{}\"",
                    text
                )
            })?;
            memberships.extend(
                resp.get_group_result
                    .users
                    .into_iter()
                    .map(|u| UserGroupMembership {
                        user_name: u.user_name,
                        group_name: group_name.to_string(),
                        namespace: namespace.to_string(),
                    })
                    .collect::<Vec<UserGroupMembership>>(),
            );
        }
        Ok(memberships)
    }
}

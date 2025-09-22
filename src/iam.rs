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
use crate::client::{ManagementClient, AUTH_HEADER_KEY};
use crate::response::get_content_text;
use anyhow::{Context as _, Result};
use derive_builder::Builder;
use reqwest::header::ACCEPT;
use reqwest::Url;
use serde::{Deserialize, Serialize};

// TODO:
// - Support for `inline_policy` for user, group and role

/// Lables for IAM account, role and user.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamTag {
    /// tag key
    pub key: String,
    /// tag value
    pub value: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PermissionsBoundary {
    /// The ARN of the policy set as permissions boundary. Default: "". Updatable
    pub permissions_boundary_arn: String,
    /// The permissions boundary usage type that indicates what type of IAM resource is used as the permissions boundary for an entity. This data type can only have a value of Policy.
    pub permissions_boundary_type: String,
}

/// In ObjectScale, an IAM User is a person or application in the account.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct User {
    /// Arn that identifies the user.
    pub arn: String,
    /// ISO 8601 format DateTime when user was created.
    pub create_date: String,
    /// The path to the IAM User.
    pub path: String,
    /// Permissions boundary. Default: see PermissionsBoundary. Updatable
    #[builder(setter(skip = false), default)]
    // list users API won't return permissions_boundary
    #[serde(default)]
    pub permissions_boundary: PermissionsBoundary,
    /// Unique Id associated with the User.
    pub user_id: String,
    /// Simple name identifying the User. Required
    #[builder(setter(into))]
    pub user_name: String,
    /// List of Tags associated with the User. Default: []. Updatable
    #[builder(setter(skip = false), default)]
    pub tags: Vec<IamTag>,
    /// Namespace. Required
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ResponseMetadata {
    pub request_id: String,
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
struct IamResponse {
    pub response_metadata: ResponseMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListUser {
    pub user_name: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListUsersResult {
    pub users: Vec<ListUser>,
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
    pub(crate) fn create(client: &mut ManagementClient, user: &Self) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=CreateUser&UserName={}",
            client.endpoint, user.user_name,
        );
        let mut req = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &user.namespace);

        if !user
            .permissions_boundary
            .permissions_boundary_arn
            .is_empty()
        {
            req = req.query(&[(
                "PermissionsBoundary",
                &user.permissions_boundary.permissions_boundary_arn,
            )]);
        }
        for (index, tag) in user.tags.iter().enumerate() {
            req = req.query(&[(&format!("Tags.member.{}.Key", index + 1), &tag.key)]);
            req = req.query(&[(&format!("Tags.member.{}.Value", index + 1), &tag.value)]);
        }

        let resp = req.send()?;
        get_content_text(resp).with_context(|| "Failed to create iam user")?;
        Ok(())
    }

    pub(crate) fn get(client: &mut ManagementClient, name: &str, namespace: &str) -> Result<Self> {
        let request_url = format!("{}iam?Action=GetUser&UserName={}", client.endpoint, name,);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get iam user")?;
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

    pub(crate) fn update_permission_boundary(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
        permissions_boundary_arn: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=PutUserPermissionsBoundary&UserName={}&PermissionsBoundary={}",
            client.endpoint, user_name, permissions_boundary_arn
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)
            .with_context(|| "Failed to update iam user permissions boundary")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise PutUserPermissionsBoundaryResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn delete_permission_boundary(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteUserPermissionsBoundary&UserName={}",
            client.endpoint, user_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)
            .with_context(|| "Failed to delete iam user permissions boundary")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteUserPermissionsBoundaryResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn add_tag(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
        tags: Vec<IamTag>,
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to tag iam user")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise TagUserResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn delete_tag(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
        tags: Vec<IamTag>,
    ) -> Result<()> {
        if tags.is_empty() {
            return Ok(());
        }
        let mut request_url = format!(
            "{}iam?Action=UntagUser&UserName={}",
            client.endpoint, user_name,
        );
        for (index, tag) in tags.iter().enumerate() {
            request_url = format!("{}&TagKeys.member.{}={}", request_url, index + 1, tag.key,);
        }

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to untag iam user")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise UntagUserResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn update(client: &mut ManagementClient, user: &Self) -> Result<bool> {
        let current_user = Self::get(client, &user.user_name, &user.namespace)?;
        let mut updated = false;

        if user.permissions_boundary.permissions_boundary_arn
            != current_user.permissions_boundary.permissions_boundary_arn
        {
            updated = true;
            if !current_user
                .permissions_boundary
                .permissions_boundary_arn
                .is_empty()
            {
                Self::delete_permission_boundary(client, &user.user_name, &user.namespace)?;
            }
            if !user
                .permissions_boundary
                .permissions_boundary_arn
                .is_empty()
            {
                Self::update_permission_boundary(
                    client,
                    &user.user_name,
                    &user.namespace,
                    &user.permissions_boundary.permissions_boundary_arn,
                )?;
            }
        }

        if user.tags != current_user.tags {
            updated = true;
            if !current_user.tags.is_empty() {
                Self::delete_tag(client, &user.user_name, &user.namespace, current_user.tags)?;
            }
            if !user.tags.is_empty() {
                Self::add_tag(client, &user.user_name, &user.namespace, user.tags.clone())?;
            }
        }

        Ok(updated)
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to delete iam user")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteUserResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn list(client: &mut ManagementClient, namespace: &str) -> Result<Vec<Self>> {
        let request_url = format!("{}iam?Action=ListUsers", client.endpoint);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to list iam user")?;
        let mut resp: ListUsersResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListUsersResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut users: Vec<Self> = vec![];
        for user in resp.list_users_result.users {
            let user = Self::get(client, &user.user_name, namespace)
                .with_context(|| "Failed to list iam users")?;
            users.push(user);
        }
        while let Some(marker) = resp.list_users_result.marker {
            let request_url = format!("{}iam?Action=ListUsers&Marker={}", client.endpoint, marker,);
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response).with_context(|| "Failed to list iam user")?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListUsersResponse. Body was: \"{}\"",
                    text
                )
            })?;
            for user in resp.list_users_result.users {
                let user = Self::get(client, &user.user_name, namespace)
                    .with_context(|| "Failed to list iam users")?;
                users.push(user);
            }
        }
        Ok(users)
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct UserPolicyAttachment {
    /// Username of the user to attach the policy. Required
    #[builder(setter(into))]
    #[serde(default)]
    pub user_name: String,
    /// Name of the policy
    pub policy_name: String,
    /// Arn of the policy to attach. Required
    #[builder(setter(into))]
    pub policy_arn: String,
    /// Namespace. Required
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
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
        user_policy_attachment: &UserPolicyAttachment,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=AttachUserPolicy&UserName={}&PolicyArn={}",
            client.endpoint, user_policy_attachment.user_name, user_policy_attachment.policy_arn,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &user_policy_attachment.namespace)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to create user policy attachment")?;
        Ok(())
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", user_policy_attachment.namespace)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to delete user policy attachment")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text =
            get_content_text(resp).with_context(|| "Failed to list user policy attachments")?;
        let mut resp: ListAttachedUserPoliciesResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAttachedUserPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut attachments: Vec<UserPolicyAttachment> = vec![];
        attachments.extend(resp.list_attached_user_policies_result.attached_policies);
        while let Some(marker) = resp.list_attached_user_policies_result.marker {
            let request_url = format!(
                "{}iam?Action=ListAttachedUserPolicies&UserName={}&Marker={}",
                client.endpoint, user_name, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)
                .with_context(|| "Failed to list user policy attachments")?;
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

/// IAM User access key
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
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
    /// The status of the access key {Active | Inactive}. No need to set value during creation, by default is Active. Updatable
    pub status: String,
    /// The name of the user that the access key is associated with. Required
    #[builder(setter(into))]
    pub user_name: String,
    /// Namespace. Required
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to create user access key")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to update user access key")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to delete user access key")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to list user access keys")?;
        let mut resp: ListAccessKeysResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListAccessKeysResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut access_keys: Vec<AccessKey> = vec![];
        access_keys.extend(resp.list_access_keys_result.access_key_metadata);
        while let Some(marker) = resp.list_access_keys_result.marker {
            let request_url = format!(
                "{}iam?Action=ListAccessKeys&UserName={}&Marker={}",
                client.endpoint, user_name, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text =
                get_content_text(response).with_context(|| "Failed to list user access keys")?;
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

/// IAM policies are documents in JSON format that define permissions for an operation regardless of the method that you use to perform the operation.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
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
    /// A friendly description of the policy. Default: ""
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
    /// The friendly name of the policy. Required.
    #[builder(setter(into))]
    pub policy_name: String,
    /// The date and time, in ISO 8601 date-time format, when the policy was created.
    pub update_date: String,
    /// The policy document in JSON format. Required. Updatable.
    #[builder(setter(into))]
    #[serde(default)]
    pub policy_document: String,
    /// Namespace. Required.
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
struct PolicyVersion {
    pub create_date: String,
    pub document: String,
    pub is_default_version: bool,
    pub version_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetPolicyVersionResult {
    pub policy_version: PolicyVersion,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetPolicyVersionResponse {
    pub response_metadata: ResponseMetadata,
    pub get_policy_version_result: GetPolicyVersionResult,
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

// TODO: Support update with CreatePolicyVersion && DeletePolicyVersion && SetDefaultPolicyVersion
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to create policy")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get policy")?;
        let resp: GetPolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetPolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut policy = resp.get_policy_result.policy;
        policy.namespace = namespace.to_string();
        policy.policy_document =
            Self::get_version(client, policy_arn, &policy.default_version_id, namespace)?;
        Ok(policy)
    }

    pub(crate) fn get_version(
        client: &mut ManagementClient,
        policy_arn: &str,
        version_id: &str,
        namespace: &str,
    ) -> Result<String> {
        let request_url = format!(
            "{}iam?Action=GetPolicyVersion&PolicyArn={}&VersionId={}",
            client.endpoint, policy_arn, version_id,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get policy version")?;
        let resp: GetPolicyVersionResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetPolicyVersionResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(resp.get_policy_version_result.policy_version.document)
    }

    pub(crate) fn create_version(
        client: &mut ManagementClient,
        policy_arn: &str,
        policy_document: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=CreatePolicyVersion&PolicyArn={}&PolicyDocument={}&SetAsDefault=true",
            client.endpoint, policy_arn, policy_document,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let _ = get_content_text(resp).with_context(|| "Failed to create policy version")?;
        Ok(())
    }

    pub(crate) fn update(client: &mut ManagementClient, policy: Policy) -> Result<bool> {
        let mut state = false;
        let current_policy = Self::get(client, &policy.arn, &policy.namespace)?;
        if policy.policy_document != current_policy.policy_document {
            state = true;
            Self::create_version(
                client,
                &policy.arn,
                &policy.policy_document,
                &policy.namespace,
            )?;
        }
        Ok(state)
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to delete policy")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to list policies")?;
        let mut resp: ListPoliciesResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListPoliciesResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut policies: Vec<Policy> = vec![];
        policies.extend(resp.list_policies_result.policies);
        while let Some(marker) = resp.list_policies_result.marker {
            let request_url = format!(
                "{}iam?Action=ListPolicies&Marker={}",
                client.endpoint, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response).with_context(|| "Failed to list policies")?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
            policies.extend(resp.list_policies_result.policies);
        }
        for policy in policies.iter_mut() {
            policy.namespace = namespace.to_string();
            policy.policy_document =
                Self::get_version(client, &policy.arn, &policy.default_version_id, namespace)?;
        }
        Ok(policies)
    }
}

/// A Group is a collection of Users. You can use groups to specify permissions for a collection of users.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct Group {
    /// Arn that identifies the Group.
    pub arn: String,
    /// ISO 8601 format DateTime when group was created.
    pub create_date: String,
    /// The path to the IAM Group.
    pub path: String,
    /// Unique Id associated with the Group.
    pub group_id: String,
    /// Simple name identifying the Group. Required.
    #[builder(setter(into))]
    pub group_name: String,
    /// Namespace. Required.
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
struct SimpleUser {
    pub user_name: String,
    pub arn: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetGroupResult {
    pub group: Group,
    pub users: Vec<SimpleUser>,
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to create group")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get group")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to delete group")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to list groups")?;
        let mut resp: ListGroupsResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListGroupsResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut groups: Vec<Group> = vec![];
        groups.extend(resp.list_groups_result.groups);
        while let Some(marker) = resp.list_groups_result.marker {
            let request_url =
                format!("{}iam?Action=ListGroups&Marker={}", client.endpoint, marker,);
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response).with_context(|| "Failed to list groups")?;
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

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct GroupPolicyAttachment {
    /// Name of the group to attach the policy. Required
    #[builder(setter(into))]
    #[serde(default)]
    pub group_name: String,
    /// Name of the policy to attach
    pub policy_name: String,
    /// Arn of the policy to attach. Required
    #[builder(setter(into))]
    pub policy_arn: String,
    /// Namespace. Required
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
        group_policy_attachment: &GroupPolicyAttachment,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=AttachGroupPolicy&GroupName={}&PolicyArn={}",
            client.endpoint, group_policy_attachment.group_name, group_policy_attachment.policy_arn,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &group_policy_attachment.namespace)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to create group policy attachment")?;
        Ok(())
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", group_policy_attachment.namespace)
            .send()?;
        let text =
            get_content_text(resp).with_context(|| "Failed to delete group policy attachment")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text =
            get_content_text(resp).with_context(|| "Failed to list group policy attachments")?;
        let mut resp: ListAttachedGroupPoliciesResponse = serde_json::from_str(&text)
            .with_context(|| {
                format!(
                    "Unable to deserialise ListAttachedGroupPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut attachments: Vec<GroupPolicyAttachment> = vec![];
        attachments.extend(resp.list_attached_group_policies_result.attached_policies);
        while let Some(marker) = resp.list_attached_group_policies_result.marker {
            let request_url = format!(
                "{}iam?Action=ListAttachedGroupPolicies&GroupName={}&Marker={}",
                client.endpoint, group_name, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)
                .with_context(|| "Failed to list group policy attachments")?;
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
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct Role {
    /// Arn that identifies the role.
    pub arn: String,
    /// The trust relationship policy document that grants an entity permission to assume the role. Required.
    #[builder(setter(into))]
    pub assume_role_policy_document: String,
    /// ISO 8601 DateTime when role was created.
    pub create_date: String,
    /// The description of the IAM role. Default: "". Updatable
    #[builder(setter(into), default)]
    pub description: String,
    /// The maximum session duration (in seconds) that you want to set for the specified role. If you do not specify a value for this setting, the default maximum of one hour is applied. This setting can have a value from 1 hour to 12 hours. Default: 3600. Updatable
    #[builder(setter(skip = false), default = 3600)]
    pub max_session_duration: i64,
    /// The path to the IAM role.
    pub path: String,
    /// Unique Id associated with the role.
    pub role_id: String,
    /// Simple name identifying the role. Required
    #[builder(setter(into))]
    pub role_name: String,
    /// The list of Tags associated with the role. Default: []. Updatable
    #[builder(setter(skip = false), default)]
    pub tags: Vec<IamTag>,
    /// Permissions boundary. Default: see PermissionsBoundary. Updatable
    #[builder(setter(skip = false), default)]
    // get/list role API won't have permissions_boundary if not set
    #[serde(default)]
    pub permissions_boundary: PermissionsBoundary,
    /// Namespace. Required
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace);

        if !role.description.is_empty() {
            req = req.query(&[("Description", role.description)]);
        }
        if (3600..=3600 * 12).contains(&role.max_session_duration) {
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
        let text = get_content_text(resp).with_context(|| "Failed to create role")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get role")?;
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

    pub(crate) fn update_role(
        client: &mut ManagementClient,
        name: &str,
        namespace: &str,
        description: &str,
        max_session_duration: i64,
    ) -> Result<()> {
        let request_url = format!("{}iam?Action=UpdateRole&RoleName={}", client.endpoint, name,);
        let mut req = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace);

        req = req.query(&[("Description", description)]);
        if (3600..=3600 * 12).contains(&max_session_duration) {
            req = req.query(&[("MaxSessionDuration", max_session_duration)]);
        }

        let resp = req.send()?;
        get_content_text(resp).with_context(|| "Failed to update role")?;
        Ok(())
    }

    pub(crate) fn update_assume_role_policy(
        client: &mut ManagementClient,
        role_name: &str,
        namespace: &str,
        policy_document: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=UpdateAssumeRolePolicy&RoleName={}&PolicyDocument={}",
            client.endpoint, role_name, policy_document
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to update assume role policy")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise UpdateAssumeRolePolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn update_permission_boundary(
        client: &mut ManagementClient,
        role_name: &str,
        namespace: &str,
        permissions_boundary_arn: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=PutRolePermissionsBoundary&RoleName={}&PermissionsBoundary={}",
            client.endpoint, role_name, permissions_boundary_arn
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)
            .with_context(|| "Failed to update iam role permissions boundary")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise PutRolePermissionsBoundaryResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn delete_permission_boundary(
        client: &mut ManagementClient,
        role_name: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteRolePermissionsBoundary&RoleName={}",
            client.endpoint, role_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)
            .with_context(|| "Failed to delete iam role permissions boundary")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise DeleteRolePermissionsBoundaryResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn add_tag(
        client: &mut ManagementClient,
        role_name: &str,
        namespace: &str,
        tags: Vec<IamTag>,
    ) -> Result<()> {
        if tags.is_empty() {
            return Ok(());
        }
        let mut request_url = format!(
            "{}iam?Action=TagRole&RoleName={}",
            client.endpoint, role_name,
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to tag iam role")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise TagRoleResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn delete_tag(
        client: &mut ManagementClient,
        role_name: &str,
        namespace: &str,
        tags: Vec<IamTag>,
    ) -> Result<()> {
        if tags.is_empty() {
            return Ok(());
        }
        let mut request_url: String = format!(
            "{}iam?Action=UntagRole&RoleName={}",
            client.endpoint, role_name,
        );
        for (index, tag) in tags.iter().enumerate() {
            request_url = format!("{}&TagKeys.member.{}={}", request_url, index + 1, tag.key);
        }

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to untag iam role")?;
        let _: IamResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise UntagRoleResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(())
    }

    pub(crate) fn update(client: &mut ManagementClient, role: &Self) -> Result<bool> {
        let current_role = Self::get(client, &role.role_name, &role.namespace)?;
        let mut updated = false;

        if role.description != current_role.description
            || role.max_session_duration != current_role.max_session_duration
        {
            updated = true;
            Self::update_role(
                client,
                &role.role_name,
                &role.namespace,
                &role.description,
                role.max_session_duration,
            )?;
        }

        if role.assume_role_policy_document != current_role.assume_role_policy_document {
            updated = true;
            Self::update_assume_role_policy(
                client,
                &role.role_name,
                &role.namespace,
                &role.assume_role_policy_document,
            )?;
        }

        if role.permissions_boundary.permissions_boundary_arn
            != current_role.permissions_boundary.permissions_boundary_arn
        {
            updated = true;
            if !current_role
                .permissions_boundary
                .permissions_boundary_arn
                .is_empty()
            {
                Self::delete_permission_boundary(client, &role.role_name, &role.namespace)?;
            }
            if !role
                .permissions_boundary
                .permissions_boundary_arn
                .is_empty()
            {
                Self::update_permission_boundary(
                    client,
                    &role.role_name,
                    &role.namespace,
                    &role.permissions_boundary.permissions_boundary_arn,
                )?;
            }
        }

        if role.tags != current_role.tags {
            updated = true;
            if !current_role.tags.is_empty() {
                Self::delete_tag(client, &role.role_name, &role.namespace, current_role.tags)?;
            }
            if !role.tags.is_empty() {
                Self::add_tag(client, &role.role_name, &role.namespace, role.tags.clone())?;
            }
        }

        Ok(updated)
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to delete role")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to list roles")?;
        let mut resp: ListRolesResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListRolesResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut roles: Vec<Role> = vec![];
        roles.extend(resp.list_roles_result.roles);
        while let Some(marker) = resp.list_roles_result.marker {
            let request_url = format!("{}iam?Action=ListRoles&Marker={}", client.endpoint, marker,);
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response).with_context(|| "Failed to list roles")?;
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

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct RolePolicyAttachment {
    /// Simple name identifying the role. Required
    #[builder(setter(into))]
    #[serde(default)]
    pub role_name: String,
    pub policy_name: String,
    /// Arn that identifies the policy. Required
    #[builder(setter(into))]
    pub policy_arn: String,
    /// Namespace. Required
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
        role_policy_attachment: &RolePolicyAttachment,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=AttachRolePolicy&RoleName={}&PolicyArn={}",
            client.endpoint, role_policy_attachment.role_name, role_policy_attachment.policy_arn,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &role_policy_attachment.namespace)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to create role policy attachment")?;
        Ok(())
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", role_policy_attachment.namespace)
            .send()?;
        let text =
            get_content_text(resp).with_context(|| "Failed to delete role policy attachment")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text =
            get_content_text(resp).with_context(|| "Failed to list role policy attachments")?;
        let mut resp: ListAttachedRolePoliciesResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListAttachedRolePoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut attachments: Vec<RolePolicyAttachment> = vec![];
        attachments.extend(resp.list_attached_role_policies_result.attached_policies);
        while let Some(marker) = resp.list_attached_role_policies_result.marker {
            let request_url = format!(
                "{}iam?Action=ListAttachedRolePolicies&RoleName={}&Marker={}",
                client.endpoint, role_name, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)
                .with_context(|| "Failed to list role policy attachments")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get entities for policy")?;
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
        while let Some(marker) = resp.list_entities_for_policy_result.marker {
            let request_url = format!(
                "{}iam?Action=ListEntitiesForPolicy&PolicyArn={}&PolicyUsageFilter={}&Marker={}",
                client.endpoint, policy_arn, entity_filter, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
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
struct SimpleGroup {
    pub group_name: String,
    pub arn: String,
    pub group_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListGroupsForUserResult {
    pub groups: Vec<SimpleGroup>,
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &user_group_membership.namespace)
            .send()?;
        let text =
            get_content_text(resp).with_context(|| "Failed to create user group membership")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", user_group_membership.namespace)
            .send()?;
        let text =
            get_content_text(resp).with_context(|| "Failed to delete user group membership")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)
            .with_context(|| "Failed to list user group membership by user")?;
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
        while let Some(marker) = resp.list_groups_for_user_result.marker {
            let request_url = format!(
                "{}iam?Action=ListGroupsForUser&UserName={}&Marker={}",
                client.endpoint, user_name, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)
                .with_context(|| "Failed to list user group membership by user")?;
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
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp)
            .with_context(|| "Failed to list user group membership by group")?;
        let mut resp: GetGroupResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise list by group GetGroupResponse. Body was: \"{}\"",
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

        while let Some(marker) = resp.get_group_result.marker {
            let request_url = format!(
                "{}iam?Action=GetGroup&GroupName={}&Marker={}",
                client.endpoint, group_name, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)
                .with_context(|| "Failed to list user group membership by group")?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise list by group GetGroupResponse. Body was: \"{}\"",
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

/// ObjectScale IAM features for S3 work with SAML identity providers to handle authentication and SAML Assertion generation
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct SamlProvider {
    /// Arn that identifies the SAML Identity Provider.
    #[serde(default)]
    pub arn: String,
    /// The name of the provider. Required
    #[serde(default)]
    #[builder(setter(into))]
    pub name: String,
    /// ISO 8601 format DateTime when SAML Identity Provider was created.
    pub create_date: String,
    /// ISO 8601 format DateTime when SAML Identity Provider will be valid.
    pub valid_until: String,
    /// An XML document generated by an identity provider (IdP) that supports SAML 2.0. Required. Updatable
    #[builder(setter(into))]
    #[serde(default, rename = "SAMLMetadataDocument")]
    pub metadata_docucment: String,
    /// Namespace. Required
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateSamlProviderResult {
    #[serde(rename = "SAMLProviderArn")]
    pub saml_provider_arn: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateSamlProviderResponse {
    pub response_metadata: ResponseMetadata,
    #[serde(rename = "CreateSAMLProviderResult")]
    pub create_saml_provider_result: CreateSamlProviderResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetSamlProviderResponse {
    pub response_metadata: ResponseMetadata,
    #[serde(rename = "GetSAMLProviderResult")]
    pub get_saml_provider_result: SamlProvider,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UpdateSAMLProviderResponse {
    pub response_metadata: ResponseMetadata,
    pub update_saml_provider_result: CreateSamlProviderResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListSamlProvidersResult {
    #[serde(rename = "SAMLProviderList")]
    pub saml_provider_list: Vec<SamlProvider>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListSamlProvidersResponse {
    pub response_metadata: ResponseMetadata,
    #[serde(rename = "ListSAMLProvidersResult")]
    pub list_saml_provider_result: ListSamlProvidersResult,
}

fn get_name_from_arn(arn: &str) -> String {
    arn.split('/').collect::<Vec<&str>>()[1].to_string()
}

impl SamlProvider {
    pub(crate) fn create(client: &mut ManagementClient, provider: Self) -> Result<Self> {
        let request_url = format!(
            "{}iam?Action=CreateSAMLProvider&Name={}&SAMLMetadataDocument={}",
            client.endpoint, provider.name, provider.metadata_docucment,
        );
        let namespace = provider.namespace;
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to create SAML provider")?;
        let resp: CreateSamlProviderResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise CreateSamlProviderResponse. Body was: \"{}\"",
                text
            )
        })?;
        Self::get(
            client,
            &resp.create_saml_provider_result.saml_provider_arn,
            &namespace,
        )
    }

    pub(crate) fn get(client: &mut ManagementClient, arn: &str, namespace: &str) -> Result<Self> {
        let request_url = format!(
            "{}iam?Action=GetSAMLProvider&SAMLProviderArn={}&",
            client.endpoint, arn,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get SAML provider")?;
        let resp: GetSamlProviderResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetSamlProviderResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut provider = resp.get_saml_provider_result;
        provider.arn = arn.to_string();
        provider.name = get_name_from_arn(arn);
        provider.namespace = namespace.to_string();
        Ok(provider)
    }

    pub(crate) fn update(client: &mut ManagementClient, provider: &Self) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=UpdateSAMLProvider&SAMLProviderArn={}&SAMLMetadataDocument={}",
            client.endpoint, provider.arn, provider.metadata_docucment,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &provider.namespace)
            .send()?;
        let _ = get_content_text(resp).with_context(|| "Failed to update SAML provider")?;
        Ok(())
    }

    pub(crate) fn delete(client: &mut ManagementClient, arn: &str, namespace: &str) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteSAMLProvider&SAMLProviderArn={}",
            client.endpoint, arn,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to delete SAML provider")?;
        Ok(())
    }

    pub(crate) fn list(client: &mut ManagementClient, namespace: &str) -> Result<Vec<Self>> {
        let request_url = format!("{}iam?Action=ListSAMLProviders", client.endpoint);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to list SAML providers")?;
        let mut resp: ListSamlProvidersResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListSamlProvidersResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut providers: Vec<Self> = vec![];
        for provider in resp.list_saml_provider_result.saml_provider_list {
            let provider = Self::get(client, &provider.arn, namespace)?;
            providers.push(provider);
        }
        while let Some(marker) = resp.list_saml_provider_result.marker {
            let request_url = format!(
                "{}iam?Action=ListSAMLProviders&Marker={}",
                client.endpoint, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text =
                get_content_text(response).with_context(|| "Failed to list SAML providers")?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListSamlProvidersResponse. Body was: \"{}\"",
                    text
                )
            })?;
            for provider in resp.list_saml_provider_result.saml_provider_list {
                let provider = Self::get(client, &provider.arn, namespace)?;
                providers.push(provider);
            }
        }
        Ok(providers)
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct UserInlinePolicy {
    /// Simple name identifying the user. Required
    #[builder(setter(into))]
    pub user_name: String,
    /// Simple name identifying the policy. Required
    #[builder(setter(into))]
    pub policy_name: String,
    /// The policy document in JSON format. Required
    #[builder(setter(into))]
    pub policy_document: String,
    /// Namespace. Required
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetUserPolicyResponse {
    pub response_metadata: ResponseMetadata,
    pub get_user_policy_result: UserInlinePolicy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListUserPoliciesResult {
    pub policy_names: Vec<String>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListUserPoliciesResponse {
    pub response_metadata: ResponseMetadata,
    pub list_user_policies_result: ListUserPoliciesResult,
}

impl UserInlinePolicy {
    pub(crate) fn create(client: &mut ManagementClient, user_inline_policy: &Self) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=PutUserPolicy&UserName={}&PolicyDocument={}&PolicyName={}",
            client.endpoint,
            user_inline_policy.user_name,
            user_inline_policy.policy_document,
            user_inline_policy.policy_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &user_inline_policy.namespace)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to create user inline policy")?;
        Ok(())
    }

    pub(crate) fn get(
        client: &mut ManagementClient,
        user_name: &str,
        policy_name: &str,
        namespace: &str,
    ) -> Result<Self> {
        let request_url = format!(
            "{}iam?Action=GetUserPolicy&UserName={}&PolicyName={}",
            client.endpoint, user_name, policy_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get user inline policy")?;
        let mut resp: GetUserPolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetUserPolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        resp.get_user_policy_result.namespace = namespace.to_string();
        Ok(resp.get_user_policy_result)
    }

    pub(crate) fn update(client: &mut ManagementClient, policy: &Self) -> Result<bool> {
        let current_policy = Self::get(
            client,
            &policy.user_name,
            &policy.policy_name,
            &policy.namespace,
        )?;
        // TODO: compare after pretty-printing format
        let url_string = format!(
            "http://example.com/?param={}",
            current_policy.policy_document
        );
        let url = Url::parse(&url_string).expect("Failed to parse policy document");
        let (_, value) = url.query_pairs().next().expect("policy document");
        if value != current_policy.policy_document {
            // create and update share the same request URL
            Self::create(client, policy)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        user_name: &str,
        policy_name: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteUserPolicy&UserName={}&PolicyName={}",
            client.endpoint, user_name, policy_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to delete user inline policy")?;
        Ok(())
    }

    pub(crate) fn list(
        client: &mut ManagementClient,
        user_name: &str,
        namespace: &str,
    ) -> Result<Vec<Self>> {
        let request_url = format!(
            "{}iam?Action=ListUserPolicies&UserName={}",
            client.endpoint, user_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to list user inline policies")?;
        let mut resp: ListUserPoliciesResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListUserPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut policies: Vec<Self> = vec![];
        for policy_name in resp.list_user_policies_result.policy_names.iter() {
            let policy = Self::get(client, user_name, policy_name, namespace)?;
            policies.push(policy);
        }
        while let Some(marker) = resp.list_user_policies_result.marker {
            let request_url = format!(
                "{}iam?Action=ListUserPolicies&UserName={}&Marker={}",
                client.endpoint, user_name, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)
                .with_context(|| "Failed to list user inline policies")?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListUserPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
            for policy_name in resp.list_user_policies_result.policy_names.iter() {
                let policy = Self::get(client, user_name, policy_name, namespace)?;
                policies.push(policy);
            }
        }
        Ok(policies)
    }
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(skip))]
pub struct GroupInlinePolicy {
    /// Simple name identifying the group. Required
    #[builder(setter(into))]
    pub group_name: String,
    /// Simple name identifying the policy. Required
    #[builder(setter(into))]
    pub policy_name: String,
    /// The policy document in JSON format. Required
    #[builder(setter(into))]
    pub policy_document: String,
    /// Namespace. Required
    #[builder(setter(into))]
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetGroupPolicyResponse {
    pub response_metadata: ResponseMetadata,
    pub get_group_policy_result: GroupInlinePolicy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListGroupPoliciesResult {
    pub policy_names: Vec<String>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListGroupPoliciesResponse {
    pub response_metadata: ResponseMetadata,
    pub list_group_policies_result: ListGroupPoliciesResult,
}

impl GroupInlinePolicy {
    pub(crate) fn create(client: &mut ManagementClient, group_inline_policy: &Self) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=PutGroupPolicy&GroupName={}&PolicyDocument={}&PolicyName={}",
            client.endpoint,
            group_inline_policy.group_name,
            group_inline_policy.policy_document,
            group_inline_policy.policy_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", &group_inline_policy.namespace)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to create group inline policy")?;
        Ok(())
    }

    pub(crate) fn get(
        client: &mut ManagementClient,
        group_name: &str,
        policy_name: &str,
        namespace: &str,
    ) -> Result<Self> {
        let request_url = format!(
            "{}iam?Action=GetGroupPolicy&GroupName={}&PolicyName={}",
            client.endpoint, group_name, policy_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get group inline policy")?;
        let mut resp: GetGroupPolicyResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise GetGroupPolicyResponse. Body was: \"{}\"",
                text
            )
        })?;
        resp.get_group_policy_result.namespace = namespace.to_string();
        Ok(resp.get_group_policy_result)
    }

    pub(crate) fn update(client: &mut ManagementClient, policy: &Self) -> Result<bool> {
        let current_policy = Self::get(
            client,
            &policy.group_name,
            &policy.policy_name,
            &policy.namespace,
        )?;
        // TODO: compare after pretty-printing format
        let url_string = format!(
            "http://example.com/?param={}",
            current_policy.policy_document
        );
        let url = Url::parse(&url_string).expect("Failed to parse policy document");
        let (_, value) = url.query_pairs().next().expect("policy document");
        if value != current_policy.policy_document {
            // create and update share the same request URL
            Self::create(client, policy)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        group_name: &str,
        policy_name: &str,
        namespace: &str,
    ) -> Result<()> {
        let request_url = format!(
            "{}iam?Action=DeleteGroupPolicy&GroupName={}&PolicyName={}",
            client.endpoint, group_name, policy_name,
        );

        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to delete group inline policy")?;
        Ok(())
    }

    pub(crate) fn list(
        client: &mut ManagementClient,
        group_name: &str,
        namespace: &str,
    ) -> Result<Vec<Self>> {
        let request_url = format!(
            "{}iam?Action=ListGroupPolicies&GroupName={}",
            client.endpoint, group_name,
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header("x-emc-namespace", namespace)
            .send()?;
        let text =
            get_content_text(resp).with_context(|| "Failed to list group inline policies")?;
        let mut resp: ListGroupPoliciesResponse =
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListGroupPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
        let mut policies: Vec<Self> = vec![];
        for policy_name in resp.list_group_policies_result.policy_names.iter() {
            let policy = Self::get(client, group_name, policy_name, namespace)?;
            policies.push(policy);
        }
        while let Some(marker) = resp.list_group_policies_result.marker {
            let request_url = format!(
                "{}iam?Action=ListUserPolicies&UserName={}&Marker={}",
                client.endpoint, group_name, marker,
            );
            let response = client
                .http_client
                .post(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .header("x-emc-namespace", namespace)
                .send()?;
            let text = get_content_text(response)
                .with_context(|| "Failed to list user inline policies")?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListGroupPoliciesResponse. Body was: \"{}\"",
                    text
                )
            })?;
            for policy_name in resp.list_group_policies_result.policy_names.iter() {
                let policy = Self::get(client, group_name, policy_name, namespace)?;
                policies.push(policy);
            }
        }
        Ok(policies)
    }
}

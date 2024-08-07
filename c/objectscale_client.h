/* Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved. */

#ifndef OBJECTSCALE_CLIENT_H
#define OBJECTSCALE_CLIENT_H

/* Generated with cbindgen:0.26.0 */

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * ManagementClient manages ObjectScale resources with the ObjectScale management REST APIs.
 */
typedef struct ManagementClient ManagementClient;

/**
 * ObjectstoreClient manages ObjectScale resources on ObjectStore with the ObjectScale ObjectStore REST APIs.
 */
typedef struct ObjectstoreClient ObjectstoreClient;

typedef struct RCString {
  uint8_t *ptr;
  uintptr_t len;
  uintptr_t cap;
} RCString;

/**
 * Build a new ManagementClient.
 *
 */
struct ManagementClient *new_management_client(struct RCString endpoint,
                                               struct RCString username,
                                               struct RCString password,
                                               bool insecure,
                                               struct RCString *err);

void destroy_management_client(struct ManagementClient *management_client);

struct ObjectstoreClient *management_client_new_objectstore_client(struct ManagementClient *management_client,
                                                                   struct RCString endpoint,
                                                                   struct RCString *err);

void destroy_objectstore_client(struct ObjectstoreClient *objectstore_client);

/**
 * Create an IAM account.
 *
 * account: Iam Account to create
 *
 */
struct RCString management_client_create_account(struct ManagementClient *management_client,
                                                 struct RCString account,
                                                 struct RCString *err);

/**
 * Get an IAM account.
 *
 * account_id: Id of the account
 *
 */
struct RCString management_client_get_account(struct ManagementClient *management_client,
                                              struct RCString account_id,
                                              struct RCString *err);

/**
 * Update an IAM account.
 *
 * account: Iam Account to update
 *
 */
struct RCString management_client_update_account(struct ManagementClient *management_client,
                                                 struct RCString account,
                                                 struct RCString *err);

/**
 * Delete an IAM account.
 *
 * account_id: Id of the account
 *
 */
void management_client_delete_account(struct ManagementClient *management_client,
                                      struct RCString account_id,
                                      struct RCString *err);

/**
 * List all IAM accounts.
 *
 */
struct RCString management_client_list_accounts(struct ManagementClient *management_client,
                                                struct RCString *err);

/**
 * Creates a new IAM User.
 *
 * user: IAM User to create
 *
 */
struct RCString management_client_create_user(struct ManagementClient *management_client,
                                              struct RCString user,
                                              struct RCString *err);

/**
 * Returns the information about the specified IAM User.
 *
 * user_name: The name of the user to retrieve. Cannot be empty.
 * namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
 *
 */
struct RCString management_client_get_user(struct ManagementClient *management_client,
                                           struct RCString user_name,
                                           struct RCString namespace_,
                                           struct RCString *err);

/**
 * Delete specified IAM User.
 *
 * user_name: The name of the user to delete. Cannot be empty.
 * namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
 *
 */
void management_client_delete_user(struct ManagementClient *management_client,
                                   struct RCString user_name,
                                   struct RCString namespace_,
                                   struct RCString *err);

/**
 * Lists the IAM users.
 *
 * namespace: Namespace of users(id of the account the user belongs to). Cannot be empty.
 *
 * TODO:
 * list_user won't show tags, or permissions boundary if any
 * fix it or report bug
 *
 */
struct RCString management_client_list_users(struct ManagementClient *management_client,
                                             struct RCString namespace_,
                                             struct RCString *err);

/**
 * Attaches the specified managed policy to the specified user.
 *
 * user_policy_attachment: UserPolicyAttachment to create
 *
 * PS: attach the same policy would throw error
 *
 */
struct RCString management_client_create_user_policy_attachment(struct ManagementClient *management_client,
                                                                struct RCString user_policy_attachment,
                                                                struct RCString *err);

/**
 * Remove the specified managed policy attached to the specified user.
 *
 * user_policy_attachment: UserPolicyAttachment to delete.
 *
 */
void management_client_delete_user_policy_attachment(struct ManagementClient *management_client,
                                                     struct RCString user_policy_attachment,
                                                     struct RCString *err);

/**
 * Lists all managed policies that are attached to the specified IAM user.
 *
 * user_name: The name of the user to list attached policies for. Cannot be empty.
 * namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
 *
 */
struct RCString management_client_list_user_policy_attachments(struct ManagementClient *management_client,
                                                               struct RCString user_name,
                                                               struct RCString namespace_,
                                                               struct RCString *err);

/**
 * Creates a password for the specified IAM user.
 *
 * login_profile: LoginProfile to create
 *
 */
struct RCString management_client_create_login_profile(struct ManagementClient *management_client,
                                                       struct RCString login_profile,
                                                       struct RCString *err);

/**
 * Retrieves the password for the specified IAM user
 *
 * user_name: Name of the user to delete password. Cannot be empty.
 * namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
 *
 */
struct RCString management_client_get_login_profile(struct ManagementClient *management_client,
                                                    struct RCString user_name,
                                                    struct RCString namespace_,
                                                    struct RCString *err);

/**
 * Deletes the password for the specified IAM user
 *
 * user_name: Name of the user to delete password. Cannot be empty.
 * namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
 *
 */
void management_client_delete_login_profile(struct ManagementClient *management_client,
                                            struct RCString user_name,
                                            struct RCString namespace_,
                                            struct RCString *err);

/**
 * Creates AccessKey for user.
 *
 * access_key: AccessKey to create
 *
 */
struct RCString management_client_create_access_key(struct ManagementClient *management_client,
                                                    struct RCString access_key,
                                                    struct RCString *err);

/**
 * Updates AccessKey for user.
 *
 * access_key: AccessKey to update
 *
 */
struct RCString management_client_update_access_key(struct ManagementClient *management_client,
                                                    struct RCString access_key,
                                                    struct RCString *err);

/**
 * Deletes the access key pair associated with the specified IAM user.
 *
 * access_key_id: The ID of the access key you want to delete. Cannot be empty.
 * user_name: Name of the user to delete accesskeys. Cannot be empty.
 * namespace: Namespace of the access key(id of the account the access key belongs to). Cannot be empty.
 *
 */
void management_client_delete_access_key(struct ManagementClient *management_client,
                                         struct RCString access_key_id,
                                         struct RCString user_name,
                                         struct RCString namespace_,
                                         struct RCString *err);

/**
 * Returns information about the access key IDs associated with the specified IAM user.
 *
 * user_name: Name of the user to list accesskeys. Cannot be empty.
 * namespace: Namespace of the access key(id of the account the access key belongs to). Cannot be empty.
 *
 */
struct RCString management_client_list_access_keys(struct ManagementClient *management_client,
                                                   struct RCString user_name,
                                                   struct RCString namespace_,
                                                   struct RCString *err);

/**
 * Creates account AccessKey.
 *
 * account_access_key: Account Access Key to create
 *
 */
struct RCString management_client_create_account_access_key(struct ManagementClient *management_client,
                                                            struct RCString account_access_key,
                                                            struct RCString *err);

/**
 * Updates account AccessKey.
 *
 * account_access_key: Account Access Key to update
 *
 */
struct RCString management_client_update_account_access_key(struct ManagementClient *management_client,
                                                            struct RCString account_access_key,
                                                            struct RCString *err);

/**
 * Deletes the access key pair associated with the specified IAM account.
 *
 * access_key_id: The ID of the access key. Cannot be empty.
 * account_id: The id of the account. Cannot be empty.
 *
 */
void management_client_delete_account_access_key(struct ManagementClient *management_client,
                                                 struct RCString access_key_id,
                                                 struct RCString account_id,
                                                 struct RCString *err);

/**
 * Returns information about the access key IDs associated with the specified IAM account.
 *
 * account_id: The id of the account. Cannot be empty.
 *
 */
struct RCString management_client_list_account_access_keys(struct ManagementClient *management_client,
                                                           struct RCString account_id,
                                                           struct RCString *err);

/**
 * Create a new Managed Policy.
 *
 * policy: IAM Policy to create
 *
 */
struct RCString management_client_create_policy(struct ManagementClient *management_client,
                                                struct RCString policy,
                                                struct RCString *err);

/**
 * Retrieve information about the specified Managed Policy.
 *
 * policy_arn: Arn of the policy to retrieve. Cannot be empty.
 * namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
 *
 */
struct RCString management_client_get_policy(struct ManagementClient *management_client,
                                             struct RCString policy_arn,
                                             struct RCString namespace_,
                                             struct RCString *err);

/**
 * Delete the specified Managed Policy.
 *
 * policy_arn: Arn of the policy to delete. Cannot be empty.
 * namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
 *
 */
void management_client_delete_policy(struct ManagementClient *management_client,
                                     struct RCString policy_arn,
                                     struct RCString namespace_,
                                     struct RCString *err);

/**
 * Lists IAM Managed Policies.
 *
 * namespace: Namespace of the policies(id of the account policies belongs to). Cannot be empty.
 *
 */
struct RCString management_client_list_policies(struct ManagementClient *management_client,
                                                struct RCString namespace_,
                                                struct RCString *err);

/**
 * Creates a new IAM Group.
 *
 * group: IAM Group to create
 *
 */
struct RCString management_client_create_group(struct ManagementClient *management_client,
                                               struct RCString group,
                                               struct RCString *err);

/**
 * Returns the information about the specified IAM Group.
 *
 * group_name: The name of the group to retrieve. Cannot be empty.
 * namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
 *
 */
struct RCString management_client_get_group(struct ManagementClient *management_client,
                                            struct RCString group_name,
                                            struct RCString namespace_,
                                            struct RCString *err);

/**
 * Delete specified IAM User.
 *
 * group_name: The name of the group to delete. Cannot be empty.
 * namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
 *
 */
void management_client_delete_group(struct ManagementClient *management_client,
                                    struct RCString group_name,
                                    struct RCString namespace_,
                                    struct RCString *err);

/**
 * Lists the IAM groups.
 *
 * namespace: Namespace of groups(id of the account groups belongs to). Cannot be empty.
 *
 */
struct RCString management_client_list_groups(struct ManagementClient *management_client,
                                              struct RCString namespace_,
                                              struct RCString *err);

/**
 * Attaches the specified managed policy to the specified group.
 *
 * group_policy_attachment: GroupPolicyAttachment to create
 *
 */
struct RCString management_client_create_group_policy_attachment(struct ManagementClient *management_client,
                                                                 struct RCString group_policy_attachment,
                                                                 struct RCString *err);

/**
 * Remove the specified managed policy attached to the specified group.
 *
 * group_policy_attachment: GroupPolicyAttachment to delete.
 *
 */
void management_client_delete_group_policy_attachment(struct ManagementClient *management_client,
                                                      struct RCString group_policy_attachment,
                                                      struct RCString *err);

/**
 * Lists all managed policies that are attached to the specified IAM Group.
 *
 * group_name: The name of the group to list attached policies for. Cannot be empty.
 * namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
 *
 */
struct RCString management_client_list_group_policy_attachments(struct ManagementClient *management_client,
                                                                struct RCString group_name,
                                                                struct RCString namespace_,
                                                                struct RCString *err);

/**
 * Creates a new IAM Role.
 *
 * role: IAM Role to create
 *
 */
struct RCString management_client_create_role(struct ManagementClient *management_client,
                                              struct RCString role,
                                              struct RCString *err);

/**
 * Returns the information about the specified IAM Role.
 *
 * role_name: The name of the role to retrieve. Cannot be empty.
 * namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
 *
 */
struct RCString management_client_get_role(struct ManagementClient *management_client,
                                           struct RCString role_name,
                                           struct RCString namespace_,
                                           struct RCString *err);

/**
 * Updates a new IAM Role.
 *
 * role: IAM Role to update
 *
 */
struct RCString management_client_update_role(struct ManagementClient *management_client,
                                              struct RCString role,
                                              struct RCString *err);

/**
 * Delete specified IAM Role.
 *
 * role_name: The name of the role to delete. Cannot be empty.
 * namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
 *
 */
void management_client_delete_role(struct ManagementClient *management_client,
                                   struct RCString role_name,
                                   struct RCString namespace_,
                                   struct RCString *err);

/**
 * Lists the IAM roles.
 *
 * namespace: Namespace of roles(id of the account roles belongs to). Cannot be empty.
 *
 */
struct RCString management_client_list_roles(struct ManagementClient *management_client,
                                             struct RCString namespace_,
                                             struct RCString *err);

/**
 * Attaches the specified managed policy to the specified role.
 *
 * role_policy_attachment: RolePolicyAttachment to create
 *
 */
struct RCString management_client_create_role_policy_attachment(struct ManagementClient *management_client,
                                                                struct RCString role_policy_attachment,
                                                                struct RCString *err);

/**
 * Remove the specified managed policy attached to the specified role.
 *
 * role_policy_attachment: RolePolicyAttachment to delete.
 *
 */
void management_client_delete_role_policy_attachment(struct ManagementClient *management_client,
                                                     struct RCString role_policy_attachment,
                                                     struct RCString *err);

/**
 * Lists all managed policies that are attached to the specified IAM Role.
 *
 * role_name: The name of the role to list attached policies for. Cannot be empty.
 * namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
 *
 */
struct RCString management_client_list_role_policy_attachments(struct ManagementClient *management_client,
                                                               struct RCString role_name,
                                                               struct RCString namespace_,
                                                               struct RCString *err);

/**
 * Lists all IAM users, groups, and roles that the specified managed policy is attached to.
 *
 * policy_arn: Arn of the policy to list entities for. Cannot be empty.
 * namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
 * entity_filter: The entity type to use for filtering the results. Valid values: User, Role, Group.
 * usage_filter: The policy usage method to use for filtering the results. Valid values: PermissionsPolicy, PermissionsBoundary.
 *
 */
struct RCString management_client_get_entities_for_policy(struct ManagementClient *management_client,
                                                          struct RCString policy_arn,
                                                          struct RCString namespace_,
                                                          struct RCString entity_filter,
                                                          struct RCString usage_filter,
                                                          struct RCString *err);

/**
 * Adds the specified user to the specified group.
 *
 * user_group_membership: UserGroupMembership to create.
 *
 */
struct RCString management_client_create_user_group_membership(struct ManagementClient *management_client,
                                                               struct RCString user_group_membership,
                                                               struct RCString *err);

/**
 * Removes the specified user from the specified group.
 *
 * user_group_membership: GroupPolicyAttachment to delete.
 *
 */
void management_client_delete_user_group_membership(struct ManagementClient *management_client,
                                                    struct RCString user_group_membership,
                                                    struct RCString *err);

/**
 * Lists the IAM groups that the specified IAM user belongs to.
 *
 * user_name: The name of the user to list group membership for. Cannot be empty.
 * namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
 *
 */
struct RCString management_client_list_user_group_memberships_by_user(struct ManagementClient *management_client,
                                                                      struct RCString user_name,
                                                                      struct RCString namespace_,
                                                                      struct RCString *err);

/**
 * Lists the IAM users that the specified IAM group contains.
 *
 * group_name: The name of the group to list contained users for. Cannot be empty.
 * namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
 *
 */
struct RCString management_client_list_user_group_memberships_by_group(struct ManagementClient *management_client,
                                                                       struct RCString group_name,
                                                                       struct RCString namespace_,
                                                                       struct RCString *err);

/**
 * Create an bucket.
 *
 * bucket: Bucket to create.
 *
 */
struct RCString objectstore_client_create_bucket(struct ObjectstoreClient *objectstore_client,
                                                 struct RCString bucket,
                                                 struct RCString *err);

/**
 * Gets bucket information for the specified bucket.
 *
 * name: Bucket name for which information will be retrieved. Cannot be empty.
 * namespace: Namespace associated. Cannot be empty.
 *
 */
struct RCString objectstore_client_get_bucket(struct ObjectstoreClient *objectstore_client,
                                              struct RCString name,
                                              struct RCString namespace_,
                                              struct RCString *err);

/**
 * Deletes the specified bucket.
 *
 * name: Bucket name to be deleted. Cannot be empty.
 * namespace: Namespace associated. Cannot be empty.
 * emptyBucket: If true, the contents of the bucket will be emptied as part of the delete, otherwise it will fail if the bucket is not empty.
 *
 */
void objectstore_client_delete_bucket(struct ObjectstoreClient *objectstore_client,
                                      struct RCString name,
                                      struct RCString namespace_,
                                      bool empty_bucket,
                                      struct RCString *err);

/**
 * Update an bucket.
 *
 * bucket: Bucket to update.
 *
 */
struct RCString objectstore_client_update_bucket(struct ObjectstoreClient *objectstore_client,
                                                 struct RCString bucket,
                                                 struct RCString *err);

/**
 * Gets the list of buckets for the specified namespace.
 *
 * namespace: Namespace for which buckets should be listed. Cannot be empty.
 * name_prefix: Case sensitive prefix of the Bucket name with a wild card(*). Can be empty or any_prefix_string*.
 *
 */
struct RCString objectstore_client_list_buckets(struct ObjectstoreClient *objectstore_client,
                                                struct RCString namespace_,
                                                struct RCString name_prefix,
                                                struct RCString *err);

/**
 * Creates the tenant which will associate an IAM Account within an objectstore.
 *
 * tenant: Tenant to create
 *
 */
struct RCString objectstore_client_create_tenant(struct ObjectstoreClient *objectstore_client,
                                                 struct RCString tenant,
                                                 struct RCString *err);

/**
 * Get the tenant.
 *
 * name: The associated account id. Cannot be empty.
 *
 */
struct RCString objectstore_client_get_tenant(struct ObjectstoreClient *objectstore_client,
                                              struct RCString name,
                                              struct RCString *err);

/**
 * Updates Tenant details like default_bucket_size and alias.
 *
 * tenant: Tenant to update
 *
 */
struct RCString objectstore_client_update_tenant(struct ObjectstoreClient *objectstore_client,
                                                 struct RCString tenant,
                                                 struct RCString *err);

/**
 * Delete the tenant from an object store. Tenant must not own any buckets.
 *
 * name: The associated account id. Cannot be empty.
 *
 */
void objectstore_client_delete_tenant(struct ObjectstoreClient *objectstore_client,
                                      struct RCString name,
                                      struct RCString *err);

/**
 * Get the list of tenants.
 *
 * name_prefix: Case sensitive prefix of the tenant name with a wild card(*). Can be empty or any_prefix_string*.
 *
 */
struct RCString objectstore_client_list_tenants(struct ObjectstoreClient *objectstore_client,
                                                struct RCString name_prefix,
                                                struct RCString *err);

void free_rcstring(struct RCString rcstring);

#endif /* OBJECTSCALE_CLIENT_H */

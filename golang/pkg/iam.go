package pkg

// #include "objectscale_client.h"
import "C"

// IAM User access key
type AccessKey struct {
	// The Id of this access key
	AccessKeyId string `attr:"access_key_id"`
	// The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the access key was created.
	CreateDate string `attr:"create_date"`
	// The secret key
	SecretAccessKey string `attr:"secret_access_key"`
	// The status of the access key {Active | Inactive}
	Status string `attr:"status"`
	// The name of the user that the access key is associated with.
	UserName string `attr:"user_name"`
	//
	Namespace string `attr:"namespace"`
}

// An ObjectScale Account is a logical construct that corresponds to a customer business unit, tenant, project, and so on.
type Account struct {
	// The Id of the account
	AccountId string `attr:"account_id"`
	// The name/id of the object scale that the account is associated with
	Objscale string `attr:"objscale"`
	// The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the account created
	CreateDate string `attr:"create_date"`
	// Indicate if encryption is enabled for the account
	EncryptionEnabled bool `attr:"encryption_enabled"`
	// account disabled
	AccountDisabled bool `attr:"account_disabled"`
	// An Alias for an account
	Alias string `attr:"alias"`
	// The description for an account
	Description string `attr:"description"`
	// protection enabled
	ProtectionEnabled bool `attr:"protection_enabled"`
	// Tso id
	TsoId string `attr:"tso_id"`
	// Labels
	Tags []Tag `attr:"tags"`
}

// IAM Account access key
type AccountAccessKey struct {
	// The Id of this access key
	AccessKeyId string `attr:"access_key_id"`
	// The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the access key was created.
	CreateDate string `attr:"create_date"`
	// The secret key
	SecretAccessKey string `attr:"secret_access_key"`
	// The status of the access key {Active | Inactive}
	Status string `attr:"status"`
	// The name of the user that the access key is associated with.
	AccountId string `attr:"account_id"`
}

type EntitiesForPolicy struct {
	//
	Users []string `attr:"users"`
	//
	Groups []string `attr:"groups"`
	//
	Roles []string `attr:"roles"`
}

// A Group is a collection of Users. You can use groups to specify permissions for a collection of users.
type Group struct {
	// Arn that identifies the Group.
	Arn string `attr:"arn"`
	// ISO 8601 format DateTime when group was created.
	CreateDate string `attr:"create_date"`
	// The path to the IAM Group.
	Path string `attr:"path"`
	// Unique Id associated with the Group.
	GroupId string `attr:"group_id"`
	// Simple name identifying the Group.
	GroupName string `attr:"group_name"`
	//
	Namespace string `attr:"namespace"`
}

type GroupPolicyAttachment struct {
	//
	GroupName string `attr:"group_name"`
	//
	PolicyName string `attr:"policy_name"`
	//
	PolicyArn string `attr:"policy_arn"`
	//
	Namespace string `attr:"namespace"`
}

type LoginProfile struct {
	//
	CreateDate string `attr:"create_date"`
	//
	UserName string `attr:"user_name"`
	//
	PasswordResetRequired bool `attr:"password_reset_required"`
	//
	Password string `attr:"password"`
	//
	Namespace string `attr:"namespace"`
}

type PermissionsBoundary struct {
	// The ARN of the policy set as permissions boundary.
	PermissionsBoundaryArn string `attr:"permissions_boundary_arn"`
	// The permissions boundary usage type that indicates what type of IAM resource is used as the permissions boundary for an entity. This data type can only have a value of Policy.
	PermissionsBoundaryType string `attr:"permissions_boundary_type"`
}

// IAM policies are documents in JSON format that define permissions for an operation regardless of the method that you use to perform the operation.
type Policy struct {
	// The resource name of the policy.
	Arn string `attr:"arn"`
	// The number of entities (users, groups, and roles) that the policy is attached to.
	AttachmentCount int64 `attr:"attachment_count"`
	// The date and time, in ISO 8601 date-time format, when the policy was created.
	CreateDate string `attr:"create_date"`
	// The identifier for the version of the policy that is set as the default version.
	DefaultVersionId string `attr:"default_version_id"`
	// A friendly description of the policy.
	Description string `attr:"description"`
	// Specifies whether the policy can be attached to user, group, or role.
	IsAttachable bool `attr:"is_attachable"`
	// The path to the policy
	Path string `attr:"path"`
	// Resource name of the policy that is used to set permissions boundary for the policy.
	PermissionsBoundaryUsageCount int64 `attr:"permissions_boundary_usage_count"`
	// The stable and unique string identifying the policy.
	PolicyId string `attr:"policy_id"`
	// The friendly name of the policy.
	PolicyName string `attr:"policy_name"`
	// The date and time, in ISO 8601 date-time format, when the policy was created.
	UpdateDate string `attr:"update_date"`
	//
	PolicyDocument string `attr:"policy_document"`
	//
	Namespace string `attr:"namespace"`
}

// A role is similar to a user, in that it is an identity with permission policies that determine what the identity can and cannot do.
type Role struct {
	// Arn that identifies the role.
	Arn string `attr:"arn"`
	// The trust relationship policy document that grants an entity permission to assume the role.
	AssumeRolePolicyDocument string `attr:"assume_role_policy_document"`
	// ISO 8601 DateTime when role was created.
	CreateDate string `attr:"create_date"`
	// The description of the IAM role.
	Description string `attr:"description"`
	// The maximum session duration (in seconds) that you want to set for the specified role.
	MaxSessionDuration int32 `attr:"max_session_duration"`
	// The path to the IAM role.
	Path string `attr:"path"`
	// Unique Id associated with the role.
	RoleId string `attr:"role_id"`
	// Simple name identifying the role.
	RoleName string `attr:"role_name"`
	// The list of Tags associated with the role.
	Tags []Tag `attr:"tags"`
	// Permissions boundary
	PermissionsBoundary PermissionsBoundary `attr:"permissions_boundary"`
	//
	Namespace string `attr:"namespace"`
}

type RolePolicyAttachment struct {
	//
	RoleName string `attr:"role_name"`
	//
	PolicyName string `attr:"policy_name"`
	//
	PolicyArn string `attr:"policy_arn"`
	//
	Namespace string `attr:"namespace"`
}

// Lables for IAM account, role and user.
type Tag struct {
	// tag key
	Key string `attr:"key"`
	// tag value
	Value string `attr:"value"`
}

// In ObjectScale, an IAM User is a person or application in the account.
type User struct {
	// Arn that identifies the user.
	Arn string `attr:"arn"`
	// ISO 8601 format DateTime when user was created.
	CreateDate string `attr:"create_date"`
	// The path to the IAM User.
	Path string `attr:"path"`
	// Permissions boundary
	PermissionsBoundary PermissionsBoundary `attr:"permissions_boundary"`
	// Unique Id associated with the User.
	UserId string `attr:"user_id"`
	// Simple name identifying the User.
	UserName string `attr:"user_name"`
	// The list of Tags associated with the User.
	Tags []Tag `attr:"tags"`
	//
	Namespace string `attr:"namespace"`
}

type UserGroupMembership struct {
	//
	UserName string `attr:"user_name"`
	//
	GroupName string `attr:"group_name"`
	//
	Namespace string `attr:"namespace"`
}

type UserPolicyAttachment struct {
	//
	UserName string `attr:"user_name"`
	//
	PolicyName string `attr:"policy_name"`
	//
	PolicyArn string `attr:"policy_arn"`
	//
	Namespace string `attr:"namespace"`
}

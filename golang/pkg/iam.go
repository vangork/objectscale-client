package pkg

// #include "objectscale_client.h"
import "C"

// IAM User access key
type AccessKey struct {
	// The Id of this access key
	AccessKeyId string `json:"AccessKeyId" yaml:"AccessKeyId" tf:"access_key_id"`
	// The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the access key was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate" tf:"create_date"`
	// The secret key
	SecretAccessKey string `json:"SecretAccessKey" yaml:"SecretAccessKey" tf:"secret_access_key"`
	// The status of the access key {Active | Inactive}. No need to set value during creation, by default is Active. Updatable
	Status string `json:"Status" yaml:"Status" tf:"status"`
	// The name of the user that the access key is associated with. Required
	UserName string `json:"UserName" yaml:"UserName" tf:"user_name"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

type EntitiesForPolicy struct {
	//
	Users []string `json:"Users" yaml:"Users" tf:"users"`
	//
	Groups []string `json:"Groups" yaml:"Groups" tf:"groups"`
	//
	Roles []string `json:"Roles" yaml:"Roles" tf:"roles"`
}

// A Group is a collection of Users. You can use groups to specify permissions for a collection of users.
type Group struct {
	// Arn that identifies the Group.
	Arn string `json:"Arn" yaml:"Arn" tf:"arn"`
	// ISO 8601 format DateTime when group was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate" tf:"create_date"`
	// The path to the IAM Group.
	Path string `json:"Path" yaml:"Path" tf:"path"`
	// Unique Id associated with the Group.
	GroupId string `json:"GroupId" yaml:"GroupId" tf:"group_id"`
	// Simple name identifying the Group. Required.
	GroupName string `json:"GroupName" yaml:"GroupName" tf:"group_name"`
	// Namespace. Required.
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

type GroupPolicyAttachment struct {
	// Name of the group to attach the policy. Required
	GroupName string `json:"GroupName" yaml:"GroupName" tf:"group_name"`
	// Name of the policy to attach
	PolicyName string `json:"PolicyName" yaml:"PolicyName" tf:"policy_name"`
	// Arn of the policy to attach. Required
	PolicyArn string `json:"PolicyArn" yaml:"PolicyArn" tf:"policy_arn"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

// Lables for IAM account, role and user.
type IamTag struct {
	// tag key
	Key string `json:"Key" yaml:"Key" tf:"key"`
	// tag value
	Value string `json:"Value" yaml:"Value" tf:"value"`
}

type PermissionsBoundary struct {
	// The ARN of the policy set as permissions boundary. Default: "". Updatable
	PermissionsBoundaryArn string `json:"PermissionsBoundaryArn" yaml:"PermissionsBoundaryArn" tf:"permissions_boundary_arn"`
	// The permissions boundary usage type that indicates what type of IAM resource is used as the permissions boundary for an entity. This data type can only have a value of Policy.
	PermissionsBoundaryType string `json:"PermissionsBoundaryType" yaml:"PermissionsBoundaryType" tf:"permissions_boundary_type"`
}

// IAM policies are documents in JSON format that define permissions for an operation regardless of the method that you use to perform the operation.
type Policy struct {
	// The resource name of the policy.
	Arn string `json:"Arn" yaml:"Arn" tf:"arn"`
	// The number of entities (users, groups, and roles) that the policy is attached to.
	AttachmentCount int64 `json:"AttachmentCount" yaml:"AttachmentCount" tf:"attachment_count"`
	// The date and time, in ISO 8601 date-time format, when the policy was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate" tf:"create_date"`
	// The identifier for the version of the policy that is set as the default version.
	DefaultVersionId string `json:"DefaultVersionId" yaml:"DefaultVersionId" tf:"default_version_id"`
	// A friendly description of the policy. Default: ""
	Description string `json:"Description" yaml:"Description" tf:"description"`
	// Specifies whether the policy can be attached to user, group, or role.
	IsAttachable bool `json:"IsAttachable" yaml:"IsAttachable" tf:"is_attachable"`
	// The path to the policy
	Path string `json:"Path" yaml:"Path" tf:"path"`
	// Resource name of the policy that is used to set permissions boundary for the policy.
	PermissionsBoundaryUsageCount int64 `json:"PermissionsBoundaryUsageCount" yaml:"PermissionsBoundaryUsageCount" tf:"permissions_boundary_usage_count"`
	// The stable and unique string identifying the policy.
	PolicyId string `json:"PolicyId" yaml:"PolicyId" tf:"policy_id"`
	// The friendly name of the policy. Required.
	PolicyName string `json:"PolicyName" yaml:"PolicyName" tf:"policy_name"`
	// The date and time, in ISO 8601 date-time format, when the policy was created.
	UpdateDate string `json:"UpdateDate" yaml:"UpdateDate" tf:"update_date"`
	// The policy document in JSON format. Required. Updatable.
	PolicyDocument string `json:"PolicyDocument" yaml:"PolicyDocument" tf:"policy_document"`
	// Namespace. Required.
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

// A role is similar to a user, in that it is an identity with permission policies that determine what the identity can and cannot do.
type Role struct {
	// Arn that identifies the role.
	Arn string `json:"Arn" yaml:"Arn" tf:"arn"`
	// The trust relationship policy document that grants an entity permission to assume the role. Required.
	AssumeRolePolicyDocument string `json:"AssumeRolePolicyDocument" yaml:"AssumeRolePolicyDocument" tf:"assume_role_policy_document"`
	// ISO 8601 DateTime when role was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate" tf:"create_date"`
	// The description of the IAM role. Default: "". Updatable
	Description string `json:"Description" yaml:"Description" tf:"description"`
	// The maximum session duration (in seconds) that you want to set for the specified role. If you do not specify a value for this setting, the default maximum of one hour is applied. This setting can have a value from 1 hour to 12 hours. Default: 3600. Updatable
	MaxSessionDuration int64 `json:"MaxSessionDuration" yaml:"MaxSessionDuration" tf:"max_session_duration"`
	// The path to the IAM role.
	Path string `json:"Path" yaml:"Path" tf:"path"`
	// Unique Id associated with the role.
	RoleId string `json:"RoleId" yaml:"RoleId" tf:"role_id"`
	// Simple name identifying the role. Required
	RoleName string `json:"RoleName" yaml:"RoleName" tf:"role_name"`
	// The list of Tags associated with the role. Default: []. Updatable
	Tags []IamTag `json:"Tags" yaml:"Tags" tf:"tags"`
	// Permissions boundary. Default: see PermissionsBoundary. Updatable
	PermissionsBoundary PermissionsBoundary `json:"PermissionsBoundary" yaml:"PermissionsBoundary" tf:"permissions_boundary"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

type RolePolicyAttachment struct {
	// Simple name identifying the role. Required
	RoleName string `json:"RoleName" yaml:"RoleName" tf:"role_name"`
	//
	PolicyName string `json:"PolicyName" yaml:"PolicyName" tf:"policy_name"`
	// Arn that identifies the policy. Required
	PolicyArn string `json:"PolicyArn" yaml:"PolicyArn" tf:"policy_arn"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

// ObjectScale IAM features for S3 work with SAML identity providers to handle authentication and SAML Assertion generation
type SamlProvider struct {
	// Arn that identifies the SAML Identity Provider.
	Arn string `json:"Arn" yaml:"Arn" tf:"arn"`
	// The name of the provider. Required
	Name string `json:"Name" yaml:"Name" tf:"name"`
	// ISO 8601 format DateTime when SAML Identity Provider was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate" tf:"create_date"`
	// ISO 8601 format DateTime when SAML Identity Provider will be valid.
	ValidUntil string `json:"ValidUntil" yaml:"ValidUntil" tf:"valid_until"`
	// An XML document generated by an identity provider (IdP) that supports SAML 2.0. Required. Updatable
	MetadataDocucment string `json:"SAMLMetadataDocument" yaml:"SAMLMetadataDocument" tf:"metadata_docucment"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

// In ObjectScale, an IAM User is a person or application in the account.
type User struct {
	// Arn that identifies the user.
	Arn string `json:"Arn" yaml:"Arn" tf:"arn"`
	// ISO 8601 format DateTime when user was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate" tf:"create_date"`
	// The path to the IAM User.
	Path string `json:"Path" yaml:"Path" tf:"path"`
	// Permissions boundary. Default: see PermissionsBoundary. Updatable
	PermissionsBoundary PermissionsBoundary `json:"PermissionsBoundary" yaml:"PermissionsBoundary" tf:"permissions_boundary"`
	// Unique Id associated with the User.
	UserId string `json:"UserId" yaml:"UserId" tf:"user_id"`
	// Simple name identifying the User. Required
	UserName string `json:"UserName" yaml:"UserName" tf:"user_name"`
	// List of Tags associated with the User. Default: [] Updatable
	Tags []IamTag `json:"Tags" yaml:"Tags" tf:"tags"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

type UserGroupMembership struct {
	//
	UserName string `json:"UserName" yaml:"UserName" tf:"user_name"`
	//
	GroupName string `json:"GroupName" yaml:"GroupName" tf:"group_name"`
	//
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

type UserPolicyAttachment struct {
	// Username of the user to attach the policy. Required
	UserName string `json:"UserName" yaml:"UserName" tf:"user_name"`
	// Name of the policy
	PolicyName string `json:"PolicyName" yaml:"PolicyName" tf:"policy_name"`
	// Arn of the policy to attach. Required
	PolicyArn string `json:"PolicyArn" yaml:"PolicyArn" tf:"policy_arn"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace" tf:"namespace"`
}

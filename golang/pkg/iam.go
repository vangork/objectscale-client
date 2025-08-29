package pkg

// #include "objectscale_client.h"
import "C"

// IAM User access key
type AccessKey struct {
	// The Id of this access key
	AccessKeyId string `json:"AccessKeyId" yaml:"AccessKeyId"`
	// The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the access key was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate"`
	// The secret key
	SecretAccessKey string `json:"SecretAccessKey" yaml:"SecretAccessKey"`
	// The status of the access key {Active | Inactive}. Updatable
	Status string `json:"Status" yaml:"Status"`
	// The name of the user that the access key is associated with. Required
	UserName string `json:"UserName" yaml:"UserName"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

type EntitiesForPolicy struct {
	//
	Users []string `json:"Users" yaml:"Users"`
	//
	Groups []string `json:"Groups" yaml:"Groups"`
	//
	Roles []string `json:"Roles" yaml:"Roles"`
}

// A Group is a collection of Users. You can use groups to specify permissions for a collection of users.
type Group struct {
	// Arn that identifies the Group.
	Arn string `json:"Arn" yaml:"Arn"`
	// ISO 8601 format DateTime when group was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate"`
	// The path to the IAM Group.
	Path string `json:"Path" yaml:"Path"`
	// Unique Id associated with the Group.
	GroupId string `json:"GroupId" yaml:"GroupId"`
	// Simple name identifying the Group. Required.
	GroupName string `json:"GroupName" yaml:"GroupName"`
	// Namespace. Required.
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

type GroupPolicyAttachment struct {
	// Name of the group to attach the policy. Required
	GroupName string `json:"GroupName" yaml:"GroupName"`
	// Name of the policy to attach
	PolicyName string `json:"PolicyName" yaml:"PolicyName"`
	// Arn of the policy to attach. Required
	PolicyArn string `json:"PolicyArn" yaml:"PolicyArn"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

// Lables for IAM account, role and user.
type IamTag struct {
	// tag key
	Key string `json:"Key" yaml:"Key"`
	// tag value
	Value string `json:"Value" yaml:"Value"`
}

type PermissionsBoundary struct {
	// The ARN of the policy set as permissions boundary.
	PermissionsBoundaryArn string `json:"PermissionsBoundaryArn" yaml:"PermissionsBoundaryArn"`
	// The permissions boundary usage type that indicates what type of IAM resource is used as the permissions boundary for an entity. This data type can only have a value of Policy.
	PermissionsBoundaryType string `json:"PermissionsBoundaryType" yaml:"PermissionsBoundaryType"`
}

// IAM policies are documents in JSON format that define permissions for an operation regardless of the method that you use to perform the operation.
type Policy struct {
	// The resource name of the policy.
	Arn string `json:"Arn" yaml:"Arn"`
	// The number of entities (users, groups, and roles) that the policy is attached to.
	AttachmentCount int64 `json:"AttachmentCount" yaml:"AttachmentCount"`
	// The date and time, in ISO 8601 date-time format, when the policy was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate"`
	// The identifier for the version of the policy that is set as the default version.
	DefaultVersionId string `json:"DefaultVersionId" yaml:"DefaultVersionId"`
	// A friendly description of the policy.
	Description string `json:"Description" yaml:"Description"`
	// Specifies whether the policy can be attached to user, group, or role.
	IsAttachable bool `json:"IsAttachable" yaml:"IsAttachable"`
	// The path to the policy
	Path string `json:"Path" yaml:"Path"`
	// Resource name of the policy that is used to set permissions boundary for the policy.
	PermissionsBoundaryUsageCount int64 `json:"PermissionsBoundaryUsageCount" yaml:"PermissionsBoundaryUsageCount"`
	// The stable and unique string identifying the policy.
	PolicyId string `json:"PolicyId" yaml:"PolicyId"`
	// The friendly name of the policy. Required.
	PolicyName string `json:"PolicyName" yaml:"PolicyName"`
	// The date and time, in ISO 8601 date-time format, when the policy was created.
	UpdateDate string `json:"UpdateDate" yaml:"UpdateDate"`
	// The policy document in JSON format. Required.
	PolicyDocument string `json:"PolicyDocument" yaml:"PolicyDocument"`
	// Namespace. Required.
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

// A role is similar to a user, in that it is an identity with permission policies that determine what the identity can and cannot do.
type Role struct {
	// Arn that identifies the role.
	Arn string `json:"Arn" yaml:"Arn"`
	// The trust relationship policy document that grants an entity permission to assume the role. Required.
	AssumeRolePolicyDocument string `json:"AssumeRolePolicyDocument" yaml:"AssumeRolePolicyDocument"`
	// ISO 8601 DateTime when role was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate"`
	// The description of the IAM role. Updatable
	Description string `json:"Description" yaml:"Description"`
	// The maximum session duration (in seconds) that you want to set for the specified role.
	MaxSessionDuration int64 `json:"MaxSessionDuration" yaml:"MaxSessionDuration"`
	// The path to the IAM role.
	Path string `json:"Path" yaml:"Path"`
	// Unique Id associated with the role.
	RoleId string `json:"RoleId" yaml:"RoleId"`
	// Simple name identifying the role. Required
	RoleName string `json:"RoleName" yaml:"RoleName"`
	// The list of Tags associated with the role. Updatable
	Tags []IamTag `json:"Tags" yaml:"Tags"`
	// Permissions boundary. Updatable
	PermissionsBoundary PermissionsBoundary `json:"PermissionsBoundary" yaml:"PermissionsBoundary"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

type RolePolicyAttachment struct {
	// Simple name identifying the role. Required
	RoleName string `json:"RoleName" yaml:"RoleName"`
	//
	PolicyName string `json:"PolicyName" yaml:"PolicyName"`
	// Arn that identifies the policy. Required
	PolicyArn string `json:"PolicyArn" yaml:"PolicyArn"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

// ObjectScale IAM features for S3 work with SAML identity providers to handle authentication and SAML Assertion generation
type SamlProvider struct {
	// Arn that identifies the SAML Identity Provider.
	Arn string `json:"Arn" yaml:"Arn"`
	//
	Name string `json:"Name" yaml:"Name"`
	// ISO 8601 format DateTime when SAML Identity Provider was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate"`
	// ISO 8601 format DateTime when SAML Identity Provider will be valid.
	ValidUntil string `json:"ValidUntil" yaml:"ValidUntil"`
	//
	MetadataDocucment string `json:"SAMLMetadataDocument" yaml:"SAMLMetadataDocument"`
	//
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

// In ObjectScale, an IAM User is a person or application in the account.
type User struct {
	// Arn that identifies the user.
	Arn string `json:"Arn" yaml:"Arn"`
	// ISO 8601 format DateTime when user was created.
	CreateDate string `json:"CreateDate" yaml:"CreateDate"`
	// The path to the IAM User.
	Path string `json:"Path" yaml:"Path"`
	// Permissions boundary. Updatable
	PermissionsBoundary PermissionsBoundary `json:"PermissionsBoundary" yaml:"PermissionsBoundary"`
	// Unique Id associated with the User.
	UserId string `json:"UserId" yaml:"UserId"`
	// Simple name identifying the User. Required
	UserName string `json:"UserName" yaml:"UserName"`
	// List of Tags associated with the User. Updatable
	Tags []IamTag `json:"Tags" yaml:"Tags"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

type UserGroupMembership struct {
	//
	UserName string `json:"UserName" yaml:"UserName"`
	//
	GroupName string `json:"GroupName" yaml:"GroupName"`
	//
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

type UserPolicyAttachment struct {
	// Username of the user to attach the policy.. Required
	UserName string `json:"UserName" yaml:"UserName"`
	// Name of the policy
	PolicyName string `json:"PolicyName" yaml:"PolicyName"`
	// Arn of the policy to attach.. Required
	PolicyArn string `json:"PolicyArn" yaml:"PolicyArn"`
	// Namespace. Required
	Namespace string `json:"Namespace" yaml:"Namespace"`
}

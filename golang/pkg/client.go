package pkg

// #include "objectscale_client.h"
import "C"
import (
	"encoding/json"
	"gopkg.in/yaml.v3"
)

// ManagementClient manages ObjectScale resources with the ObjectScale management REST APIs.
type ManagementClient struct {
	managementClient *C.ManagementClient
}

// Build a new ManagementClient.
func NewManagementClient(endpoint string, username string, password string, insecure bool) (*ManagementClient, error) {
	msg := C.RCString{}
	cEndpoint := intoRCString(endpoint)
	cUsername := intoRCString(username)
	cPassword := intoRCString(password)
	cInsecure := cbool(insecure)

	managementClient, err := C.new_management_client(cEndpoint, cUsername, cPassword, cInsecure, &msg)
	if err != nil {
		return nil, errorWithMessage(err, msg)
	}
	return &ManagementClient{
		managementClient,
	}, nil
}

// Close the ManagementClient.
// Make sure to call this function when you are done using the ManagementClient.
func (managementClient *ManagementClient) Close() {
	C.destroy_management_client(managementClient.managementClient)
}

// Creates a new IAM User.
//
// user: IAM User to create
func (managementClient *ManagementClient) CreateUser(user *User) (*User, error) {
	msg := C.RCString{}
	userJson, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	cUser := intoRCString(string(userJson))

	cUserFn, errFn := C.management_client_create_user(managementClient.managementClient, cUser, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	userYamlFn := fromRCString(cUserFn)
	var userFn User
	errUnmarshal := yaml.Unmarshal([]byte(userYamlFn), &userFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &userFn, nil
}

// Retrieve IAM user.
//
// name: The name of the user to retrieve.
// namespace: ECS namespace IAM entity belongs to
func (managementClient *ManagementClient) GetUser(name string, namespace string) (*User, error) {
	msg := C.RCString{}
	cName := intoRCString(name)
	cNamespace := intoRCString(namespace)

	cUserFn, errFn := C.management_client_get_user(managementClient.managementClient, cName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	userYamlFn := fromRCString(cUserFn)
	var userFn User
	errUnmarshal := yaml.Unmarshal([]byte(userYamlFn), &userFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &userFn, nil
}

// Updates an IAM user.
//
// user: IAM User to be updated
func (managementClient *ManagementClient) UpdateUser(user *User) (bool, error) {
	msg := C.RCString{}
	userJson, err := json.Marshal(user)
	if err != nil {
		return false, err
	}
	cUser := intoRCString(string(userJson))

	state, errFn := C.management_client_update_user(managementClient.managementClient, cUser, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Delete specified IAM User.
//
// user_name: The name of the user to delete. Cannot be empty.
// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
func (managementClient *ManagementClient) DeleteUser(userName string, namespace string) error {
	msg := C.RCString{}
	cUserName := intoRCString(userName)
	cNamespace := intoRCString(namespace)

	_, errFn := C.management_client_delete_user(managementClient.managementClient, cUserName, cNamespace, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Lists the IAM users.
//
// namespace: Namespace of users(id of the account the user belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListUsers(namespace string) ([]User, error) {
	msg := C.RCString{}
	cNamespace := intoRCString(namespace)

	cUsersFn, errFn := C.management_client_list_users(managementClient.managementClient, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	usersYamlFn := fromRCString(cUsersFn)
	var usersFn []User
	errUnmarshal := yaml.Unmarshal([]byte(usersYamlFn), &usersFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return usersFn, nil
}

// Attaches the specified managed policy to the specified user.
//
// user_policy_attachment: UserPolicyAttachment to create
//
// PS: attach the same policy would throw error
func (managementClient *ManagementClient) CreateUserPolicyAttachment(userPolicyAttachment *UserPolicyAttachment) (*UserPolicyAttachment, error) {
	msg := C.RCString{}
	userPolicyAttachmentJson, err := json.Marshal(userPolicyAttachment)
	if err != nil {
		return nil, err
	}
	cUserPolicyAttachment := intoRCString(string(userPolicyAttachmentJson))

	cUserPolicyAttachmentFn, errFn := C.management_client_create_user_policy_attachment(managementClient.managementClient, cUserPolicyAttachment, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	userPolicyAttachmentYamlFn := fromRCString(cUserPolicyAttachmentFn)
	var userPolicyAttachmentFn UserPolicyAttachment
	errUnmarshal := yaml.Unmarshal([]byte(userPolicyAttachmentYamlFn), &userPolicyAttachmentFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &userPolicyAttachmentFn, nil
}

// Remove the specified managed policy attached to the specified user.
//
// user_policy_attachment: UserPolicyAttachment to delete.
func (managementClient *ManagementClient) DeleteUserPolicyAttachment(userPolicyAttachment *UserPolicyAttachment) error {
	msg := C.RCString{}
	userPolicyAttachmentJson, err := json.Marshal(userPolicyAttachment)
	if err != nil {
		return err
	}
	cUserPolicyAttachment := intoRCString(string(userPolicyAttachmentJson))

	_, errFn := C.management_client_delete_user_policy_attachment(managementClient.managementClient, cUserPolicyAttachment, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Lists all managed policies that are attached to the specified IAM user.
//
// user_name: The name of the user to list attached policies for. Cannot be empty.
// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListUserPolicyAttachments(userName string, namespace string) ([]UserPolicyAttachment, error) {
	msg := C.RCString{}
	cUserName := intoRCString(userName)
	cNamespace := intoRCString(namespace)

	cUserPolicyAttachmentsFn, errFn := C.management_client_list_user_policy_attachments(managementClient.managementClient, cUserName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	userPolicyAttachmentsYamlFn := fromRCString(cUserPolicyAttachmentsFn)
	var userPolicyAttachmentsFn []UserPolicyAttachment
	errUnmarshal := yaml.Unmarshal([]byte(userPolicyAttachmentsYamlFn), &userPolicyAttachmentsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return userPolicyAttachmentsFn, nil
}

// Creates AccessKey for user.
//
// access_key: AccessKey to create
func (managementClient *ManagementClient) CreateAccessKey(accessKey *AccessKey) (*AccessKey, error) {
	msg := C.RCString{}
	accessKeyJson, err := json.Marshal(accessKey)
	if err != nil {
		return nil, err
	}
	cAccessKey := intoRCString(string(accessKeyJson))

	cAccessKeyFn, errFn := C.management_client_create_access_key(managementClient.managementClient, cAccessKey, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accessKeyYamlFn := fromRCString(cAccessKeyFn)
	var accessKeyFn AccessKey
	errUnmarshal := yaml.Unmarshal([]byte(accessKeyYamlFn), &accessKeyFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &accessKeyFn, nil
}

// Updates AccessKey for user.
//
// access_key: AccessKey to update
func (managementClient *ManagementClient) UpdateAccessKey(accessKey *AccessKey) (bool, error) {
	msg := C.RCString{}
	accessKeyJson, err := json.Marshal(accessKey)
	if err != nil {
		return false, err
	}
	cAccessKey := intoRCString(string(accessKeyJson))

	state, errFn := C.management_client_update_access_key(managementClient.managementClient, cAccessKey, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Deletes the access key pair associated with the specified IAM user.
//
// access_key_id: The ID of the access key you want to delete. Cannot be empty.
// user_name: Name of the user to delete accesskeys. Cannot be empty.
// namespace: Namespace of the access key(id of the account the access key belongs to). Cannot be empty.
func (managementClient *ManagementClient) DeleteAccessKey(accessKeyId string, userName string, namespace string) error {
	msg := C.RCString{}
	cAccessKeyId := intoRCString(accessKeyId)
	cUserName := intoRCString(userName)
	cNamespace := intoRCString(namespace)

	_, errFn := C.management_client_delete_access_key(managementClient.managementClient, cAccessKeyId, cUserName, cNamespace, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Returns information about the access key IDs associated with the specified IAM user.
//
// user_name: Name of the user to list accesskeys. Cannot be empty.
// namespace: Namespace of the access key(id of the account the access key belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListAccessKeys(userName string, namespace string) ([]AccessKey, error) {
	msg := C.RCString{}
	cUserName := intoRCString(userName)
	cNamespace := intoRCString(namespace)

	cAccessKeysFn, errFn := C.management_client_list_access_keys(managementClient.managementClient, cUserName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accessKeysYamlFn := fromRCString(cAccessKeysFn)
	var accessKeysFn []AccessKey
	errUnmarshal := yaml.Unmarshal([]byte(accessKeysYamlFn), &accessKeysFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return accessKeysFn, nil
}

// Create a new Managed Policy.
//
// policy: IAM Policy to create
func (managementClient *ManagementClient) CreatePolicy(policy *Policy) (*Policy, error) {
	msg := C.RCString{}
	policyJson, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	cPolicy := intoRCString(string(policyJson))

	cPolicyFn, errFn := C.management_client_create_policy(managementClient.managementClient, cPolicy, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	policyYamlFn := fromRCString(cPolicyFn)
	var policyFn Policy
	errUnmarshal := yaml.Unmarshal([]byte(policyYamlFn), &policyFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &policyFn, nil
}

// Retrieve information about the specified Managed Policy.
//
// policy_arn: Arn of the policy to retrieve. Cannot be empty.
// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
func (managementClient *ManagementClient) GetPolicy(policyArn string, namespace string) (*Policy, error) {
	msg := C.RCString{}
	cPolicyArn := intoRCString(policyArn)
	cNamespace := intoRCString(namespace)

	cPolicyFn, errFn := C.management_client_get_policy(managementClient.managementClient, cPolicyArn, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	policyYamlFn := fromRCString(cPolicyFn)
	var policyFn Policy
	errUnmarshal := yaml.Unmarshal([]byte(policyYamlFn), &policyFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &policyFn, nil
}

// Delete the specified Managed Policy.
//
// policy_arn: Arn of the policy to delete. Cannot be empty.
// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
func (managementClient *ManagementClient) DeletePolicy(policyArn string, namespace string) error {
	msg := C.RCString{}
	cPolicyArn := intoRCString(policyArn)
	cNamespace := intoRCString(namespace)

	_, errFn := C.management_client_delete_policy(managementClient.managementClient, cPolicyArn, cNamespace, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Lists IAM Managed Policies.
//
// namespace: Namespace of the policies(id of the account policies belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListPolicies(namespace string) ([]Policy, error) {
	msg := C.RCString{}
	cNamespace := intoRCString(namespace)

	cPolicysFn, errFn := C.management_client_list_policies(managementClient.managementClient, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	policysYamlFn := fromRCString(cPolicysFn)
	var policysFn []Policy
	errUnmarshal := yaml.Unmarshal([]byte(policysYamlFn), &policysFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return policysFn, nil
}

// Creates a new IAM Group.
//
// group: IAM Group to create
func (managementClient *ManagementClient) CreateGroup(group *Group) (*Group, error) {
	msg := C.RCString{}
	groupJson, err := json.Marshal(group)
	if err != nil {
		return nil, err
	}
	cGroup := intoRCString(string(groupJson))

	cGroupFn, errFn := C.management_client_create_group(managementClient.managementClient, cGroup, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	groupYamlFn := fromRCString(cGroupFn)
	var groupFn Group
	errUnmarshal := yaml.Unmarshal([]byte(groupYamlFn), &groupFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &groupFn, nil
}

// Returns the information about the specified IAM Group.
//
// group_name: The name of the group to retrieve. Cannot be empty.
// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
func (managementClient *ManagementClient) GetGroup(groupName string, namespace string) (*Group, error) {
	msg := C.RCString{}
	cGroupName := intoRCString(groupName)
	cNamespace := intoRCString(namespace)

	cGroupFn, errFn := C.management_client_get_group(managementClient.managementClient, cGroupName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	groupYamlFn := fromRCString(cGroupFn)
	var groupFn Group
	errUnmarshal := yaml.Unmarshal([]byte(groupYamlFn), &groupFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &groupFn, nil
}

// Delete specified IAM User.
//
// group_name: The name of the group to delete. Cannot be empty.
// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
func (managementClient *ManagementClient) DeleteGroup(groupName string, namespace string) error {
	msg := C.RCString{}
	cGroupName := intoRCString(groupName)
	cNamespace := intoRCString(namespace)

	_, errFn := C.management_client_delete_group(managementClient.managementClient, cGroupName, cNamespace, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Lists the IAM groups.
//
// namespace: Namespace of groups(id of the account groups belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListGroups(namespace string) ([]Group, error) {
	msg := C.RCString{}
	cNamespace := intoRCString(namespace)

	cGroupsFn, errFn := C.management_client_list_groups(managementClient.managementClient, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	groupsYamlFn := fromRCString(cGroupsFn)
	var groupsFn []Group
	errUnmarshal := yaml.Unmarshal([]byte(groupsYamlFn), &groupsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return groupsFn, nil
}

// Attaches the specified managed policy to the specified group.
//
// group_policy_attachment: GroupPolicyAttachment to create
func (managementClient *ManagementClient) CreateGroupPolicyAttachment(groupPolicyAttachment *GroupPolicyAttachment) (*GroupPolicyAttachment, error) {
	msg := C.RCString{}
	groupPolicyAttachmentJson, err := json.Marshal(groupPolicyAttachment)
	if err != nil {
		return nil, err
	}
	cGroupPolicyAttachment := intoRCString(string(groupPolicyAttachmentJson))

	cGroupPolicyAttachmentFn, errFn := C.management_client_create_group_policy_attachment(managementClient.managementClient, cGroupPolicyAttachment, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	groupPolicyAttachmentYamlFn := fromRCString(cGroupPolicyAttachmentFn)
	var groupPolicyAttachmentFn GroupPolicyAttachment
	errUnmarshal := yaml.Unmarshal([]byte(groupPolicyAttachmentYamlFn), &groupPolicyAttachmentFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &groupPolicyAttachmentFn, nil
}

// Remove the specified managed policy attached to the specified group.
//
// group_policy_attachment: GroupPolicyAttachment to delete.
func (managementClient *ManagementClient) DeleteGroupPolicyAttachment(groupPolicyAttachment *GroupPolicyAttachment) error {
	msg := C.RCString{}
	groupPolicyAttachmentJson, err := json.Marshal(groupPolicyAttachment)
	if err != nil {
		return err
	}
	cGroupPolicyAttachment := intoRCString(string(groupPolicyAttachmentJson))

	_, errFn := C.management_client_delete_group_policy_attachment(managementClient.managementClient, cGroupPolicyAttachment, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Lists all managed policies that are attached to the specified IAM Group.
//
// group_name: The name of the group to list attached policies for. Cannot be empty.
// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListGroupPolicyAttachments(groupName string, namespace string) ([]GroupPolicyAttachment, error) {
	msg := C.RCString{}
	cGroupName := intoRCString(groupName)
	cNamespace := intoRCString(namespace)

	cGroupPolicyAttachmentsFn, errFn := C.management_client_list_group_policy_attachments(managementClient.managementClient, cGroupName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	groupPolicyAttachmentsYamlFn := fromRCString(cGroupPolicyAttachmentsFn)
	var groupPolicyAttachmentsFn []GroupPolicyAttachment
	errUnmarshal := yaml.Unmarshal([]byte(groupPolicyAttachmentsYamlFn), &groupPolicyAttachmentsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return groupPolicyAttachmentsFn, nil
}

// Creates a new IAM Role.
//
// role: IAM Role to create
func (managementClient *ManagementClient) CreateRole(role *Role) (*Role, error) {
	msg := C.RCString{}
	roleJson, err := json.Marshal(role)
	if err != nil {
		return nil, err
	}
	cRole := intoRCString(string(roleJson))

	cRoleFn, errFn := C.management_client_create_role(managementClient.managementClient, cRole, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	roleYamlFn := fromRCString(cRoleFn)
	var roleFn Role
	errUnmarshal := yaml.Unmarshal([]byte(roleYamlFn), &roleFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &roleFn, nil
}

// Returns the information about the specified IAM Role.
//
// role_name: The name of the role to retrieve. Cannot be empty.
// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
func (managementClient *ManagementClient) GetRole(roleName string, namespace string) (*Role, error) {
	msg := C.RCString{}
	cRoleName := intoRCString(roleName)
	cNamespace := intoRCString(namespace)

	cRoleFn, errFn := C.management_client_get_role(managementClient.managementClient, cRoleName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	roleYamlFn := fromRCString(cRoleFn)
	var roleFn Role
	errUnmarshal := yaml.Unmarshal([]byte(roleYamlFn), &roleFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &roleFn, nil
}

// Updates a new IAM Role.
//
// role: IAM Role to update
func (managementClient *ManagementClient) UpdateRole(role *Role) (bool, error) {
	msg := C.RCString{}
	roleJson, err := json.Marshal(role)
	if err != nil {
		return false, err
	}
	cRole := intoRCString(string(roleJson))

	state, errFn := C.management_client_update_role(managementClient.managementClient, cRole, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Delete specified IAM Role.
//
// role_name: The name of the role to delete. Cannot be empty.
// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
func (managementClient *ManagementClient) DeleteRole(roleName string, namespace string) error {
	msg := C.RCString{}
	cRoleName := intoRCString(roleName)
	cNamespace := intoRCString(namespace)

	_, errFn := C.management_client_delete_role(managementClient.managementClient, cRoleName, cNamespace, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Lists the IAM roles.
//
// namespace: Namespace of roles(id of the account roles belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListRoles(namespace string) ([]Role, error) {
	msg := C.RCString{}
	cNamespace := intoRCString(namespace)

	cRolesFn, errFn := C.management_client_list_roles(managementClient.managementClient, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	rolesYamlFn := fromRCString(cRolesFn)
	var rolesFn []Role
	errUnmarshal := yaml.Unmarshal([]byte(rolesYamlFn), &rolesFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return rolesFn, nil
}

// Attaches the specified managed policy to the specified role.
//
// role_policy_attachment: RolePolicyAttachment to create
func (managementClient *ManagementClient) CreateRolePolicyAttachment(rolePolicyAttachment *RolePolicyAttachment) (*RolePolicyAttachment, error) {
	msg := C.RCString{}
	rolePolicyAttachmentJson, err := json.Marshal(rolePolicyAttachment)
	if err != nil {
		return nil, err
	}
	cRolePolicyAttachment := intoRCString(string(rolePolicyAttachmentJson))

	cRolePolicyAttachmentFn, errFn := C.management_client_create_role_policy_attachment(managementClient.managementClient, cRolePolicyAttachment, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	rolePolicyAttachmentYamlFn := fromRCString(cRolePolicyAttachmentFn)
	var rolePolicyAttachmentFn RolePolicyAttachment
	errUnmarshal := yaml.Unmarshal([]byte(rolePolicyAttachmentYamlFn), &rolePolicyAttachmentFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &rolePolicyAttachmentFn, nil
}

// Remove the specified managed policy attached to the specified role.
//
// role_policy_attachment: RolePolicyAttachment to delete.
func (managementClient *ManagementClient) DeleteRolePolicyAttachment(rolePolicyAttachment *RolePolicyAttachment) error {
	msg := C.RCString{}
	rolePolicyAttachmentJson, err := json.Marshal(rolePolicyAttachment)
	if err != nil {
		return err
	}
	cRolePolicyAttachment := intoRCString(string(rolePolicyAttachmentJson))

	_, errFn := C.management_client_delete_role_policy_attachment(managementClient.managementClient, cRolePolicyAttachment, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Lists all managed policies that are attached to the specified IAM Role.
//
// role_name: The name of the role to list attached policies for. Cannot be empty.
// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListRolePolicyAttachments(roleName string, namespace string) ([]RolePolicyAttachment, error) {
	msg := C.RCString{}
	cRoleName := intoRCString(roleName)
	cNamespace := intoRCString(namespace)

	cRolePolicyAttachmentsFn, errFn := C.management_client_list_role_policy_attachments(managementClient.managementClient, cRoleName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	rolePolicyAttachmentsYamlFn := fromRCString(cRolePolicyAttachmentsFn)
	var rolePolicyAttachmentsFn []RolePolicyAttachment
	errUnmarshal := yaml.Unmarshal([]byte(rolePolicyAttachmentsYamlFn), &rolePolicyAttachmentsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return rolePolicyAttachmentsFn, nil
}

// Lists all IAM users, groups, and roles that the specified managed policy is attached to.
//
// policy_arn: Arn of the policy to list entities for. Cannot be empty.
// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
// entity_filter: The entity type to use for filtering the results. Valid values: User, Role, Group.
// usage_filter: The policy usage method to use for filtering the results. Valid values: PermissionsPolicy, PermissionsBoundary.
func (managementClient *ManagementClient) GetEntitiesForPolicy(policyArn string, namespace string, entityFilter string, usageFilter string) (*EntitiesForPolicy, error) {
	msg := C.RCString{}
	cPolicyArn := intoRCString(policyArn)
	cNamespace := intoRCString(namespace)
	cEntityFilter := intoRCString(entityFilter)
	cUsageFilter := intoRCString(usageFilter)

	cEntitiesForPolicyFn, errFn := C.management_client_get_entities_for_policy(managementClient.managementClient, cPolicyArn, cNamespace, cEntityFilter, cUsageFilter, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	entitiesForPolicyYamlFn := fromRCString(cEntitiesForPolicyFn)
	var entitiesForPolicyFn EntitiesForPolicy
	errUnmarshal := yaml.Unmarshal([]byte(entitiesForPolicyYamlFn), &entitiesForPolicyFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &entitiesForPolicyFn, nil
}

// Adds the specified user to the specified group.
//
// user_group_membership: UserGroupMembership to create.
func (managementClient *ManagementClient) CreateUserGroupMembership(userGroupMembership *UserGroupMembership) (*UserGroupMembership, error) {
	msg := C.RCString{}
	userGroupMembershipJson, err := json.Marshal(userGroupMembership)
	if err != nil {
		return nil, err
	}
	cUserGroupMembership := intoRCString(string(userGroupMembershipJson))

	cUserGroupMembershipFn, errFn := C.management_client_create_user_group_membership(managementClient.managementClient, cUserGroupMembership, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	userGroupMembershipYamlFn := fromRCString(cUserGroupMembershipFn)
	var userGroupMembershipFn UserGroupMembership
	errUnmarshal := yaml.Unmarshal([]byte(userGroupMembershipYamlFn), &userGroupMembershipFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &userGroupMembershipFn, nil
}

// Removes the specified user from the specified group.
//
// user_group_membership: GroupPolicyAttachment to delete.
func (managementClient *ManagementClient) DeleteUserGroupMembership(userGroupMembership *UserGroupMembership) error {
	msg := C.RCString{}
	userGroupMembershipJson, err := json.Marshal(userGroupMembership)
	if err != nil {
		return err
	}
	cUserGroupMembership := intoRCString(string(userGroupMembershipJson))

	_, errFn := C.management_client_delete_user_group_membership(managementClient.managementClient, cUserGroupMembership, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Lists the IAM groups that the specified IAM user belongs to.
//
// user_name: The name of the user to list group membership for. Cannot be empty.
// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListUserGroupMembershipsByUser(userName string, namespace string) ([]UserGroupMembership, error) {
	msg := C.RCString{}
	cUserName := intoRCString(userName)
	cNamespace := intoRCString(namespace)

	cUserGroupMembershipsFn, errFn := C.management_client_list_user_group_memberships_by_user(managementClient.managementClient, cUserName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	userGroupMembershipsYamlFn := fromRCString(cUserGroupMembershipsFn)
	var userGroupMembershipsFn []UserGroupMembership
	errUnmarshal := yaml.Unmarshal([]byte(userGroupMembershipsYamlFn), &userGroupMembershipsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return userGroupMembershipsFn, nil
}

// Create SAML Identity Provider
//
// provider: SAML provider to create
func (managementClient *ManagementClient) CreateSamlProvider(provider *SamlProvider) (*SamlProvider, error) {
	msg := C.RCString{}
	providerJson, err := json.Marshal(provider)
	if err != nil {
		return nil, err
	}
	cProvider := intoRCString(string(providerJson))

	cSamlProviderFn, errFn := C.management_client_create_saml_provider(managementClient.managementClient, cProvider, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	samlProviderYamlFn := fromRCString(cSamlProviderFn)
	var samlProviderFn SamlProvider
	errUnmarshal := yaml.Unmarshal([]byte(samlProviderYamlFn), &samlProviderFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &samlProviderFn, nil
}

// Retrieve the SAML IdP document.
//
// arn: The name of the provider to retrieve.
// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
func (managementClient *ManagementClient) GetSamlProvider(arn string, namespace string) (*SamlProvider, error) {
	msg := C.RCString{}
	cArn := intoRCString(arn)
	cNamespace := intoRCString(namespace)

	cSamlProviderFn, errFn := C.management_client_get_saml_provider(managementClient.managementClient, cArn, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	samlProviderYamlFn := fromRCString(cSamlProviderFn)
	var samlProviderFn SamlProvider
	errUnmarshal := yaml.Unmarshal([]byte(samlProviderYamlFn), &samlProviderFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &samlProviderFn, nil
}

// Update the SAML Identity Provider.
//
// role: SAML Identity Provider to update
func (managementClient *ManagementClient) UpdateSamlProvider(provider *SamlProvider) (bool, error) {
	msg := C.RCString{}
	providerJson, err := json.Marshal(provider)
	if err != nil {
		return false, err
	}
	cProvider := intoRCString(string(providerJson))

	state, errFn := C.management_client_update_saml_provider(managementClient.managementClient, cProvider, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Delete the SAML Identity Provider.
//
// arn: The ARN of the provider to delete.
// namespace: ECS namespace IAM entity belongs to
func (managementClient *ManagementClient) DeleteSamlProvider(arn string, namespace string) error {
	msg := C.RCString{}
	cArn := intoRCString(arn)
	cNamespace := intoRCString(namespace)

	_, errFn := C.management_client_delete_saml_provider(managementClient.managementClient, cArn, cNamespace, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// List the SAML Identity Providers.
//
// namespace: ECS namespace IAM entity belongs to
func (managementClient *ManagementClient) ListSamlProviders(namespace string) ([]SamlProvider, error) {
	msg := C.RCString{}
	cNamespace := intoRCString(namespace)

	cSamlProvidersFn, errFn := C.management_client_list_saml_providers(managementClient.managementClient, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	samlProvidersYamlFn := fromRCString(cSamlProvidersFn)
	var samlProvidersFn []SamlProvider
	errUnmarshal := yaml.Unmarshal([]byte(samlProvidersYamlFn), &samlProvidersFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return samlProvidersFn, nil
}

// Lists the IAM users that the specified IAM group contains.
//
// group_name: The name of the group to list contained users for. Cannot be empty.
// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
func (managementClient *ManagementClient) ListUserGroupMembershipsByGroup(groupName string, namespace string) ([]UserGroupMembership, error) {
	msg := C.RCString{}
	cGroupName := intoRCString(groupName)
	cNamespace := intoRCString(namespace)

	cUserGroupMembershipsFn, errFn := C.management_client_list_user_group_memberships_by_group(managementClient.managementClient, cGroupName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	userGroupMembershipsYamlFn := fromRCString(cUserGroupMembershipsFn)
	var userGroupMembershipsFn []UserGroupMembership
	errUnmarshal := yaml.Unmarshal([]byte(userGroupMembershipsYamlFn), &userGroupMembershipsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return userGroupMembershipsFn, nil
}

// Gets the list of buckets for the specified namespace.
//
// namespace: Namespace for which buckets should be listed. Cannot be empty.
// name_prefix: Case sensitive prefix of the Bucket name with a wild card(*). Can be empty or any_prefix_string*.
func (managementClient *ManagementClient) ListBuckets(namespace string, namePrefix string) ([]Bucket, error) {
	msg := C.RCString{}
	cNamespace := intoRCString(namespace)
	cNamePrefix := intoRCString(namePrefix)

	cBucketsFn, errFn := C.management_client_list_buckets(managementClient.managementClient, cNamespace, cNamePrefix, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	bucketsYamlFn := fromRCString(cBucketsFn)
	var bucketsFn []Bucket
	errUnmarshal := yaml.Unmarshal([]byte(bucketsYamlFn), &bucketsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return bucketsFn, nil
}

// Create an bucket.
//
// bucket: Bucket to create.
func (managementClient *ManagementClient) CreateBucket(bucket *Bucket) (*Bucket, error) {
	msg := C.RCString{}
	bucketJson, err := json.Marshal(bucket)
	if err != nil {
		return nil, err
	}
	cBucket := intoRCString(string(bucketJson))

	cBucketFn, errFn := C.management_client_create_bucket(managementClient.managementClient, cBucket, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	bucketYamlFn := fromRCString(cBucketFn)
	var bucketFn Bucket
	errUnmarshal := yaml.Unmarshal([]byte(bucketYamlFn), &bucketFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &bucketFn, nil
}

// Gets bucket information for the specified bucket.
//
// name: Bucket name for which information will be retrieved. Cannot be empty.
// namespace: Namespace associated. Cannot be empty.
func (managementClient *ManagementClient) GetBucket(name string, namespace string) (*Bucket, error) {
	msg := C.RCString{}
	cName := intoRCString(name)
	cNamespace := intoRCString(namespace)

	cBucketFn, errFn := C.management_client_get_bucket(managementClient.managementClient, cName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	bucketYamlFn := fromRCString(cBucketFn)
	var bucketFn Bucket
	errUnmarshal := yaml.Unmarshal([]byte(bucketYamlFn), &bucketFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &bucketFn, nil
}

// Update an bucket.
//
// bucket: Bucket to update.
func (managementClient *ManagementClient) UpdateBucket(bucket *Bucket) (bool, error) {
	msg := C.RCString{}
	bucketJson, err := json.Marshal(bucket)
	if err != nil {
		return false, err
	}
	cBucket := intoRCString(string(bucketJson))

	state, errFn := C.management_client_update_bucket(managementClient.managementClient, cBucket, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Deletes the specified bucket.
//
// name: Bucket name to be deleted. Cannot be empty.
// namespace: Namespace associated. Cannot be empty.
// emptyBucket: If true, the contents of the bucket will be emptied as part of the delete, otherwise it will fail if the bucket is not empty.
func (managementClient *ManagementClient) DeleteBucket(name string, namespace string, emptyBucket bool) error {
	msg := C.RCString{}
	cName := intoRCString(name)
	cNamespace := intoRCString(namespace)
	cEmptyBucket := cbool(emptyBucket)

	_, errFn := C.management_client_delete_bucket(managementClient.managementClient, cName, cNamespace, cEmptyBucket, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Creates a namespace with the given details.
//
// namespace: Namespace to create
func (managementClient *ManagementClient) CreateNamespace(namespace *Namespace) (*Namespace, error) {
	msg := C.RCString{}
	namespaceJson, err := json.Marshal(namespace)
	if err != nil {
		return nil, err
	}
	cNamespace := intoRCString(string(namespaceJson))

	cNamespaceFn, errFn := C.management_client_create_namespace(managementClient.managementClient, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	namespaceYamlFn := fromRCString(cNamespaceFn)
	var namespaceFn Namespace
	errUnmarshal := yaml.Unmarshal([]byte(namespaceYamlFn), &namespaceFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &namespaceFn, nil
}

// Gets the details for the given namespace.
//
// id: Namespace identifier for which details needs to be retrieved.
func (managementClient *ManagementClient) GetNamespace(id string) (*Namespace, error) {
	msg := C.RCString{}
	cId := intoRCString(id)

	cNamespaceFn, errFn := C.management_client_get_namespace(managementClient.managementClient, cId, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	namespaceYamlFn := fromRCString(cNamespaceFn)
	var namespaceFn Namespace
	errUnmarshal := yaml.Unmarshal([]byte(namespaceYamlFn), &namespaceFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &namespaceFn, nil
}

// Update a namespace with the given details.
//
// namespace: Namespace to be updated
func (managementClient *ManagementClient) UpdateNamespace(namespace *Namespace) (bool, error) {
	msg := C.RCString{}
	namespaceJson, err := json.Marshal(namespace)
	if err != nil {
		return false, err
	}
	cNamespace := intoRCString(string(namespaceJson))

	state, errFn := C.management_client_update_namespace(managementClient.managementClient, cNamespace, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Deactivates and deletes the given namespace and all associated user mappings.
//
// id: An active namespace identifier which needs to be deactivated/deleted
func (managementClient *ManagementClient) DeleteNamespace(id string) error {
	msg := C.RCString{}
	cId := intoRCString(id)

	_, errFn := C.management_client_delete_namespace(managementClient.managementClient, cId, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Gets the list of all configured namespaces.
//
// name_prefix: Case sensitive prefix of the Namespace name with a wild card(*) Ex : any_prefix_string*.
func (managementClient *ManagementClient) ListNamespaces(namePrefix string) ([]Namespace, error) {
	msg := C.RCString{}
	cNamePrefix := intoRCString(namePrefix)

	cNamespacesFn, errFn := C.management_client_list_namespaces(managementClient.managementClient, cNamePrefix, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	namespacesYamlFn := fromRCString(cNamespacesFn)
	var namespacesFn []Namespace
	errUnmarshal := yaml.Unmarshal([]byte(namespacesYamlFn), &namespacesFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return namespacesFn, nil
}

// Creates local users for the VDC.
//
// user: ManagementUser to create
func (managementClient *ManagementClient) CreateManagementUser(user *ManagementUser) (*ManagementUser, error) {
	msg := C.RCString{}
	userJson, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	cUser := intoRCString(string(userJson))

	cManagementUserFn, errFn := C.management_client_create_management_user(managementClient.managementClient, cUser, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	managementUserYamlFn := fromRCString(cManagementUserFn)
	var managementUserFn ManagementUser
	errUnmarshal := yaml.Unmarshal([]byte(managementUserYamlFn), &managementUserFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &managementUserFn, nil
}

// Gets details for the specified local management user.
//
// id: User identifier for which local user information needs to be retrieved
func (managementClient *ManagementClient) GetManagementUser(id string) (*ManagementUser, error) {
	msg := C.RCString{}
	cId := intoRCString(id)

	cManagementUserFn, errFn := C.management_client_get_management_user(managementClient.managementClient, cId, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	managementUserYamlFn := fromRCString(cManagementUserFn)
	var managementUserFn ManagementUser
	errUnmarshal := yaml.Unmarshal([]byte(managementUserYamlFn), &managementUserFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &managementUserFn, nil
}

// Updates user details for the specified local management user.
//
// user: ManagementUser to be updated
func (managementClient *ManagementClient) UpdateManagementUser(user *ManagementUser) (bool, error) {
	msg := C.RCString{}
	userJson, err := json.Marshal(user)
	if err != nil {
		return false, err
	}
	cUser := intoRCString(string(userJson))

	state, errFn := C.management_client_update_management_user(managementClient.managementClient, cUser, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Deletes local management user information for the specified user identifier.
//
// id: User identifier for which local user information needs to be deleted.
func (managementClient *ManagementClient) DeleteManagementUser(id string) error {
	msg := C.RCString{}
	cId := intoRCString(id)

	_, errFn := C.management_client_delete_management_user(managementClient.managementClient, cId, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Gets all configured local management users.
func (managementClient *ManagementClient) ListManagementUsers() ([]ManagementUser, error) {
	msg := C.RCString{}

	cManagementUsersFn, errFn := C.management_client_list_management_users(managementClient.managementClient, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	managementUsersYamlFn := fromRCString(cManagementUsersFn)
	var managementUsersFn []ManagementUser
	errUnmarshal := yaml.Unmarshal([]byte(managementUsersYamlFn), &managementUsersFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return managementUsersFn, nil
}

// Creates a user for a specified namespace.
//
// user: ObjectUser to create
func (managementClient *ManagementClient) CreateObjectUser(user *ObjectUser) (*ObjectUser, error) {
	msg := C.RCString{}
	userJson, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	cUser := intoRCString(string(userJson))

	cObjectUserFn, errFn := C.management_client_create_object_user(managementClient.managementClient, cUser, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	objectUserYamlFn := fromRCString(cObjectUserFn)
	var objectUserFn ObjectUser
	errUnmarshal := yaml.Unmarshal([]byte(objectUserYamlFn), &objectUserFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &objectUserFn, nil
}

// Gets user details for the specified user belong to the specified namespace.
//
// name: Valid user identifier
// namespace: The namespace to which user belong
func (managementClient *ManagementClient) GetObjectUser(name string, namespace string) (*ObjectUser, error) {
	msg := C.RCString{}
	cName := intoRCString(name)
	cNamespace := intoRCString(namespace)

	cObjectUserFn, errFn := C.management_client_get_object_user(managementClient.managementClient, cName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	objectUserYamlFn := fromRCString(cObjectUserFn)
	var objectUserFn ObjectUser
	errUnmarshal := yaml.Unmarshal([]byte(objectUserYamlFn), &objectUserFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &objectUserFn, nil
}

// Updates user details for the specified object user.
//
// user: ObjectUser to be updated
func (managementClient *ManagementClient) UpdateObjectUser(user *ObjectUser) (bool, error) {
	msg := C.RCString{}
	userJson, err := json.Marshal(user)
	if err != nil {
		return false, err
	}
	cUser := intoRCString(string(userJson))

	state, errFn := C.management_client_update_object_user(managementClient.managementClient, cUser, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Deletes the specified user and its secret keys.
//
// name: User to be deleted.
// namespace: Namespace identifier to associate with the user
func (managementClient *ManagementClient) DeleteObjectUser(name string, namespace string) error {
	msg := C.RCString{}
	cName := intoRCString(name)
	cNamespace := intoRCString(namespace)

	_, errFn := C.management_client_delete_object_user(managementClient.managementClient, cName, cNamespace, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Gets identifiers for all configured users.
func (managementClient *ManagementClient) ListObjectUsers() ([]ObjectUser, error) {
	msg := C.RCString{}

	cObjectUsersFn, errFn := C.management_client_list_object_users(managementClient.managementClient, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	objectUsersYamlFn := fromRCString(cObjectUsersFn)
	var objectUsersFn []ObjectUser
	errUnmarshal := yaml.Unmarshal([]byte(objectUsersYamlFn), &objectUsersFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return objectUsersFn, nil
}

// Get the certificate chain being used by ECS
func (managementClient *ManagementClient) GetVdcKeystore() (*VdcKeystore, error) {
	msg := C.RCString{}

	cVdcKeystoreFn, errFn := C.management_client_get_vdc_keystore(managementClient.managementClient, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	vdcKeystoreYamlFn := fromRCString(cVdcKeystoreFn)
	var vdcKeystoreFn VdcKeystore
	errUnmarshal := yaml.Unmarshal([]byte(vdcKeystoreYamlFn), &vdcKeystoreFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &vdcKeystoreFn, nil
}

// Set the certificate chain being used by ECS.
//
// keystore: VdcKeystore to be updated
func (managementClient *ManagementClient) UpdateVdcKeystore(keystore *VdcKeystore) (bool, error) {
	msg := C.RCString{}
	keystoreJson, err := json.Marshal(keystore)
	if err != nil {
		return false, err
	}
	cKeystore := intoRCString(string(keystoreJson))

	state, errFn := C.management_client_update_vdc_keystore(managementClient.managementClient, cKeystore, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Gets the details for a VDC the identify of which is specified by its name.
//
// name: VDC name for which VDC Information is to be retrieved
func (managementClient *ManagementClient) GetVdc(name string) (*Vdc, error) {
	msg := C.RCString{}
	cName := intoRCString(name)

	cVdcFn, errFn := C.management_client_get_vdc(managementClient.managementClient, cName, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	vdcYamlFn := fromRCString(cVdcFn)
	var vdcFn Vdc
	errUnmarshal := yaml.Unmarshal([]byte(vdcYamlFn), &vdcFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &vdcFn, nil
}

// Deactivates and deletes a VDC.
//
// id: VDC identifier for which VDC Information needs to be deleted
func (managementClient *ManagementClient) DeleteVdc(id string) error {
	msg := C.RCString{}
	cId := intoRCString(id)

	_, errFn := C.management_client_delete_vdc(managementClient.managementClient, cId, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Gets all details of all configured VDCs.
func (managementClient *ManagementClient) ListVdcs() ([]Vdc, error) {
	msg := C.RCString{}

	cVdcsFn, errFn := C.management_client_list_vdcs(managementClient.managementClient, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	vdcsYamlFn := fromRCString(cVdcsFn)
	var vdcsFn []Vdc
	errUnmarshal := yaml.Unmarshal([]byte(vdcsYamlFn), &vdcsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return vdcsFn, nil
}

// Gets the details for the specified storage pool.
//
// id: Storage pool identifier to be retrieved
func (managementClient *ManagementClient) GetStoragePool(id string) (*StoragePool, error) {
	msg := C.RCString{}
	cId := intoRCString(id)

	cStoragePoolFn, errFn := C.management_client_get_storage_pool(managementClient.managementClient, cId, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	storagePoolYamlFn := fromRCString(cStoragePoolFn)
	var storagePoolFn StoragePool
	errUnmarshal := yaml.Unmarshal([]byte(storagePoolYamlFn), &storagePoolFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &storagePoolFn, nil
}

// Updates storage pool for the specified identifier..
//
// sp: Storage pool to be updated
func (managementClient *ManagementClient) UpdateStoragePool(sp *StoragePool) (bool, error) {
	msg := C.RCString{}
	spJson, err := json.Marshal(sp)
	if err != nil {
		return false, err
	}
	cSp := intoRCString(string(spJson))

	state, errFn := C.management_client_update_storage_pool(managementClient.managementClient, cSp, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Gets a list of storage pools from the local VDC.
func (managementClient *ManagementClient) ListStoragePools() ([]StoragePool, error) {
	msg := C.RCString{}

	cStoragePoolsFn, errFn := C.management_client_list_storage_pools(managementClient.managementClient, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	storagePoolsYamlFn := fromRCString(cStoragePoolsFn)
	var storagePoolsFn []StoragePool
	errUnmarshal := yaml.Unmarshal([]byte(storagePoolsYamlFn), &storagePoolsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return storagePoolsFn, nil
}

// Creates a replication group that includes the specified storage pools
//
// rg: ReplicationGroup to create
func (managementClient *ManagementClient) CreateReplicationGroup(rg *ReplicationGroup) (*ReplicationGroup, error) {
	msg := C.RCString{}
	rgJson, err := json.Marshal(rg)
	if err != nil {
		return nil, err
	}
	cRg := intoRCString(string(rgJson))

	cReplicationGroupFn, errFn := C.management_client_create_replication_group(managementClient.managementClient, cRg, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	replicationGroupYamlFn := fromRCString(cReplicationGroupFn)
	var replicationGroupFn ReplicationGroup
	errUnmarshal := yaml.Unmarshal([]byte(replicationGroupYamlFn), &replicationGroupFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &replicationGroupFn, nil
}

// Gets the details for the specified replication group.
//
// id: Replication group identifier for which details needs to be retrieved
func (managementClient *ManagementClient) GetReplicationGroup(id string) (*ReplicationGroup, error) {
	msg := C.RCString{}
	cId := intoRCString(id)

	cReplicationGroupFn, errFn := C.management_client_get_replication_group(managementClient.managementClient, cId, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	replicationGroupYamlFn := fromRCString(cReplicationGroupFn)
	var replicationGroupFn ReplicationGroup
	errUnmarshal := yaml.Unmarshal([]byte(replicationGroupYamlFn), &replicationGroupFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &replicationGroupFn, nil
}

// Updates the name and description for a replication group.
//
// rg: Replication group which details needs to be updated
func (managementClient *ManagementClient) UpdateReplicationGroup(rg *ReplicationGroup) (bool, error) {
	msg := C.RCString{}
	rgJson, err := json.Marshal(rg)
	if err != nil {
		return false, err
	}
	cRg := intoRCString(string(rgJson))

	state, errFn := C.management_client_update_replication_group(managementClient.managementClient, cRg, &msg)
	if errFn != nil {
		return false, errorWithMessage(errFn, msg)
	}
	return bool(state), nil

}

// Lists all configured replication groups.
func (managementClient *ManagementClient) ListReplicationGroups() ([]ReplicationGroup, error) {
	msg := C.RCString{}

	cReplicationGroupsFn, errFn := C.management_client_list_replication_groups(managementClient.managementClient, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	replicationGroupsYamlFn := fromRCString(cReplicationGroupsFn)
	var replicationGroupsFn []ReplicationGroup
	errUnmarshal := yaml.Unmarshal([]byte(replicationGroupsYamlFn), &replicationGroupsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return replicationGroupsFn, nil
}

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

func (managementClient *ManagementClient) NewObjectstoreClient(endpoint string) (*ObjectstoreClient, error) {
	msg := C.RCString{}
	cEndpoint := intoRCString(endpoint)

	objectstoreClient, err := C.management_client_new_objectstore_client(managementClient.managementClient, cEndpoint, &msg)
	if err != nil {
		return nil, errorWithMessage(err, msg)
	}
	return &ObjectstoreClient{
		objectstoreClient,
	}, nil
}

// Close the ObjectstoreClient.
// Make sure to call this function when you are done using the objectstore client.
func (objectstoreClient *ObjectstoreClient) Close() {
	C.destroy_objectstore_client(objectstoreClient.objectstoreClient)
}

// Create an IAM account.
//
// account: Iam Account to create
func (managementClient *ManagementClient) CreateAccount(account *Account) (*Account, error) {
	msg := C.RCString{}
	accountJson, err := json.Marshal(account)
	if err != nil {
		return nil, err
	}
	cAccount := intoRCString(string(accountJson))

	cAccountFn, errFn := C.management_client_create_account(managementClient.managementClient, cAccount, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accountJsonFn := fromRCString(cAccountFn)
	var accountFn Account
	errUnmarshal := json.Unmarshal([]byte(accountJsonFn), &accountFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &accountFn, nil
}

// Get an IAM account.
//
// account_id: Id of the account
func (managementClient *ManagementClient) GetAccount(accountId string) (*Account, error) {
	msg := C.RCString{}
	cAccountId := intoRCString(accountId)

	cAccountFn, errFn := C.management_client_get_account(managementClient.managementClient, cAccountId, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accountJsonFn := fromRCString(cAccountFn)
	var accountFn Account
	errUnmarshal := json.Unmarshal([]byte(accountJsonFn), &accountFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &accountFn, nil
}

// Update an IAM account.
//
// account: Iam Account to update
func (managementClient *ManagementClient) UpdateAccount(account *Account) (*Account, error) {
	msg := C.RCString{}
	accountJson, err := json.Marshal(account)
	if err != nil {
		return nil, err
	}
	cAccount := intoRCString(string(accountJson))

	cAccountFn, errFn := C.management_client_update_account(managementClient.managementClient, cAccount, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accountJsonFn := fromRCString(cAccountFn)
	var accountFn Account
	errUnmarshal := json.Unmarshal([]byte(accountJsonFn), &accountFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &accountFn, nil
}

// Delete an IAM account.
//
// account_id: Id of the account
func (managementClient *ManagementClient) DeleteAccount(accountId string) error {
	msg := C.RCString{}
	cAccountId := intoRCString(accountId)

	_, errFn := C.management_client_delete_account(managementClient.managementClient, cAccountId, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// List all IAM accounts.
func (managementClient *ManagementClient) ListAccounts() ([]Account, error) {
	msg := C.RCString{}

	cAccountsFn, errFn := C.management_client_list_accounts(managementClient.managementClient, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accountsJsonFn := fromRCString(cAccountsFn)
	var accountsFn []Account
	errUnmarshal := json.Unmarshal([]byte(accountsJsonFn), &accountsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return accountsFn, nil
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
	userJsonFn := fromRCString(cUserFn)
	var userFn User
	errUnmarshal := json.Unmarshal([]byte(userJsonFn), &userFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &userFn, nil
}

// Returns the information about the specified IAM User.
//
// user_name: The name of the user to retrieve. Cannot be empty.
// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
func (managementClient *ManagementClient) GetUser(userName string, namespace string) (*User, error) {
	msg := C.RCString{}
	cUserName := intoRCString(userName)
	cNamespace := intoRCString(namespace)

	cUserFn, errFn := C.management_client_get_user(managementClient.managementClient, cUserName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	userJsonFn := fromRCString(cUserFn)
	var userFn User
	errUnmarshal := json.Unmarshal([]byte(userJsonFn), &userFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &userFn, nil
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
//
// TODO:
// list_user won't show tags, or permissions boundary if any
// fix it or report bug
func (managementClient *ManagementClient) ListUsers(namespace string) ([]User, error) {
	msg := C.RCString{}
	cNamespace := intoRCString(namespace)

	cUsersFn, errFn := C.management_client_list_users(managementClient.managementClient, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	usersJsonFn := fromRCString(cUsersFn)
	var usersFn []User
	errUnmarshal := json.Unmarshal([]byte(usersJsonFn), &usersFn)
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
	userPolicyAttachmentJsonFn := fromRCString(cUserPolicyAttachmentFn)
	var userPolicyAttachmentFn UserPolicyAttachment
	errUnmarshal := json.Unmarshal([]byte(userPolicyAttachmentJsonFn), &userPolicyAttachmentFn)
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
	userPolicyAttachmentsJsonFn := fromRCString(cUserPolicyAttachmentsFn)
	var userPolicyAttachmentsFn []UserPolicyAttachment
	errUnmarshal := json.Unmarshal([]byte(userPolicyAttachmentsJsonFn), &userPolicyAttachmentsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return userPolicyAttachmentsFn, nil
}

// Creates a password for the specified IAM user.
//
// login_profile: LoginProfile to create
func (managementClient *ManagementClient) CreateLoginProfile(loginProfile *LoginProfile) (*LoginProfile, error) {
	msg := C.RCString{}
	loginProfileJson, err := json.Marshal(loginProfile)
	if err != nil {
		return nil, err
	}
	cLoginProfile := intoRCString(string(loginProfileJson))

	cLoginProfileFn, errFn := C.management_client_create_login_profile(managementClient.managementClient, cLoginProfile, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	loginProfileJsonFn := fromRCString(cLoginProfileFn)
	var loginProfileFn LoginProfile
	errUnmarshal := json.Unmarshal([]byte(loginProfileJsonFn), &loginProfileFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &loginProfileFn, nil
}

// Retrieves the password for the specified IAM user
//
// user_name: Name of the user to delete password. Cannot be empty.
// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
func (managementClient *ManagementClient) GetLoginProfile(userName string, namespace string) (*LoginProfile, error) {
	msg := C.RCString{}
	cUserName := intoRCString(userName)
	cNamespace := intoRCString(namespace)

	cLoginProfileFn, errFn := C.management_client_get_login_profile(managementClient.managementClient, cUserName, cNamespace, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	loginProfileJsonFn := fromRCString(cLoginProfileFn)
	var loginProfileFn LoginProfile
	errUnmarshal := json.Unmarshal([]byte(loginProfileJsonFn), &loginProfileFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &loginProfileFn, nil
}

// Deletes the password for the specified IAM user
//
// user_name: Name of the user to delete password. Cannot be empty.
// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
func (managementClient *ManagementClient) DeleteLoginProfile(userName string, namespace string) error {
	msg := C.RCString{}
	cUserName := intoRCString(userName)
	cNamespace := intoRCString(namespace)

	_, errFn := C.management_client_delete_login_profile(managementClient.managementClient, cUserName, cNamespace, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

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
	accessKeyJsonFn := fromRCString(cAccessKeyFn)
	var accessKeyFn AccessKey
	errUnmarshal := json.Unmarshal([]byte(accessKeyJsonFn), &accessKeyFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &accessKeyFn, nil
}

// Updates AccessKey for user.
//
// access_key: AccessKey to update
func (managementClient *ManagementClient) UpdateAccessKey(accessKey *AccessKey) (*AccessKey, error) {
	msg := C.RCString{}
	accessKeyJson, err := json.Marshal(accessKey)
	if err != nil {
		return nil, err
	}
	cAccessKey := intoRCString(string(accessKeyJson))

	cAccessKeyFn, errFn := C.management_client_update_access_key(managementClient.managementClient, cAccessKey, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accessKeyJsonFn := fromRCString(cAccessKeyFn)
	var accessKeyFn AccessKey
	errUnmarshal := json.Unmarshal([]byte(accessKeyJsonFn), &accessKeyFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &accessKeyFn, nil
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
	accessKeysJsonFn := fromRCString(cAccessKeysFn)
	var accessKeysFn []AccessKey
	errUnmarshal := json.Unmarshal([]byte(accessKeysJsonFn), &accessKeysFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return accessKeysFn, nil
}

// Creates account AccessKey.
//
// account_access_key: Account Access Key to create
func (managementClient *ManagementClient) CreateAccountAccessKey(accountAccessKey *AccountAccessKey) (*AccountAccessKey, error) {
	msg := C.RCString{}
	accountAccessKeyJson, err := json.Marshal(accountAccessKey)
	if err != nil {
		return nil, err
	}
	cAccountAccessKey := intoRCString(string(accountAccessKeyJson))

	cAccountAccessKeyFn, errFn := C.management_client_create_account_access_key(managementClient.managementClient, cAccountAccessKey, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accountAccessKeyJsonFn := fromRCString(cAccountAccessKeyFn)
	var accountAccessKeyFn AccountAccessKey
	errUnmarshal := json.Unmarshal([]byte(accountAccessKeyJsonFn), &accountAccessKeyFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &accountAccessKeyFn, nil
}

// Updates account AccessKey.
//
// account_access_key: Account Access Key to update
func (managementClient *ManagementClient) UpdateAccountAccessKey(accountAccessKey *AccountAccessKey) (*AccountAccessKey, error) {
	msg := C.RCString{}
	accountAccessKeyJson, err := json.Marshal(accountAccessKey)
	if err != nil {
		return nil, err
	}
	cAccountAccessKey := intoRCString(string(accountAccessKeyJson))

	cAccountAccessKeyFn, errFn := C.management_client_update_account_access_key(managementClient.managementClient, cAccountAccessKey, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accountAccessKeyJsonFn := fromRCString(cAccountAccessKeyFn)
	var accountAccessKeyFn AccountAccessKey
	errUnmarshal := json.Unmarshal([]byte(accountAccessKeyJsonFn), &accountAccessKeyFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &accountAccessKeyFn, nil
}

// Deletes the access key pair associated with the specified IAM account.
//
// access_key_id: The ID of the access key. Cannot be empty.
// account_id: The id of the account. Cannot be empty.
func (managementClient *ManagementClient) DeleteAccountAccessKey(accessKeyId string, accountId string) error {
	msg := C.RCString{}
	cAccessKeyId := intoRCString(accessKeyId)
	cAccountId := intoRCString(accountId)

	_, errFn := C.management_client_delete_account_access_key(managementClient.managementClient, cAccessKeyId, cAccountId, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Returns information about the access key IDs associated with the specified IAM account.
//
// account_id: The id of the account. Cannot be empty.
func (managementClient *ManagementClient) ListAccountAccessKeys(accountId string) ([]AccountAccessKey, error) {
	msg := C.RCString{}
	cAccountId := intoRCString(accountId)

	cAccountAccessKeysFn, errFn := C.management_client_list_account_access_keys(managementClient.managementClient, cAccountId, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	accountAccessKeysJsonFn := fromRCString(cAccountAccessKeysFn)
	var accountAccessKeysFn []AccountAccessKey
	errUnmarshal := json.Unmarshal([]byte(accountAccessKeysJsonFn), &accountAccessKeysFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return accountAccessKeysFn, nil
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
	policyJsonFn := fromRCString(cPolicyFn)
	var policyFn Policy
	errUnmarshal := json.Unmarshal([]byte(policyJsonFn), &policyFn)
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
	policyJsonFn := fromRCString(cPolicyFn)
	var policyFn Policy
	errUnmarshal := json.Unmarshal([]byte(policyJsonFn), &policyFn)
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
	policysJsonFn := fromRCString(cPolicysFn)
	var policysFn []Policy
	errUnmarshal := json.Unmarshal([]byte(policysJsonFn), &policysFn)
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
	groupJsonFn := fromRCString(cGroupFn)
	var groupFn Group
	errUnmarshal := json.Unmarshal([]byte(groupJsonFn), &groupFn)
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
	groupJsonFn := fromRCString(cGroupFn)
	var groupFn Group
	errUnmarshal := json.Unmarshal([]byte(groupJsonFn), &groupFn)
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
	groupsJsonFn := fromRCString(cGroupsFn)
	var groupsFn []Group
	errUnmarshal := json.Unmarshal([]byte(groupsJsonFn), &groupsFn)
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
	groupPolicyAttachmentJsonFn := fromRCString(cGroupPolicyAttachmentFn)
	var groupPolicyAttachmentFn GroupPolicyAttachment
	errUnmarshal := json.Unmarshal([]byte(groupPolicyAttachmentJsonFn), &groupPolicyAttachmentFn)
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
	groupPolicyAttachmentsJsonFn := fromRCString(cGroupPolicyAttachmentsFn)
	var groupPolicyAttachmentsFn []GroupPolicyAttachment
	errUnmarshal := json.Unmarshal([]byte(groupPolicyAttachmentsJsonFn), &groupPolicyAttachmentsFn)
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
	roleJsonFn := fromRCString(cRoleFn)
	var roleFn Role
	errUnmarshal := json.Unmarshal([]byte(roleJsonFn), &roleFn)
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
	roleJsonFn := fromRCString(cRoleFn)
	var roleFn Role
	errUnmarshal := json.Unmarshal([]byte(roleJsonFn), &roleFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &roleFn, nil
}

// Updates a new IAM Role.
//
// role: IAM Role to update
func (managementClient *ManagementClient) UpdateRole(role *Role) (*Role, error) {
	msg := C.RCString{}
	roleJson, err := json.Marshal(role)
	if err != nil {
		return nil, err
	}
	cRole := intoRCString(string(roleJson))

	cRoleFn, errFn := C.management_client_update_role(managementClient.managementClient, cRole, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	roleJsonFn := fromRCString(cRoleFn)
	var roleFn Role
	errUnmarshal := json.Unmarshal([]byte(roleJsonFn), &roleFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &roleFn, nil
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
	rolesJsonFn := fromRCString(cRolesFn)
	var rolesFn []Role
	errUnmarshal := json.Unmarshal([]byte(rolesJsonFn), &rolesFn)
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
	rolePolicyAttachmentJsonFn := fromRCString(cRolePolicyAttachmentFn)
	var rolePolicyAttachmentFn RolePolicyAttachment
	errUnmarshal := json.Unmarshal([]byte(rolePolicyAttachmentJsonFn), &rolePolicyAttachmentFn)
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
	rolePolicyAttachmentsJsonFn := fromRCString(cRolePolicyAttachmentsFn)
	var rolePolicyAttachmentsFn []RolePolicyAttachment
	errUnmarshal := json.Unmarshal([]byte(rolePolicyAttachmentsJsonFn), &rolePolicyAttachmentsFn)
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
	entitiesForPolicyJsonFn := fromRCString(cEntitiesForPolicyFn)
	var entitiesForPolicyFn EntitiesForPolicy
	errUnmarshal := json.Unmarshal([]byte(entitiesForPolicyJsonFn), &entitiesForPolicyFn)
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
	userGroupMembershipJsonFn := fromRCString(cUserGroupMembershipFn)
	var userGroupMembershipFn UserGroupMembership
	errUnmarshal := json.Unmarshal([]byte(userGroupMembershipJsonFn), &userGroupMembershipFn)
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
	userGroupMembershipsJsonFn := fromRCString(cUserGroupMembershipsFn)
	var userGroupMembershipsFn []UserGroupMembership
	errUnmarshal := json.Unmarshal([]byte(userGroupMembershipsJsonFn), &userGroupMembershipsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return userGroupMembershipsFn, nil
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
	userGroupMembershipsJsonFn := fromRCString(cUserGroupMembershipsFn)
	var userGroupMembershipsFn []UserGroupMembership
	errUnmarshal := json.Unmarshal([]byte(userGroupMembershipsJsonFn), &userGroupMembershipsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return userGroupMembershipsFn, nil
}

// ObjectstoreClient manages ObjectScale resources on ObjectStore with the ObjectScale ObjectStore REST APIs.
type ObjectstoreClient struct {
	objectstoreClient *C.ObjectstoreClient
}

// Create an bucket.
//
// bucket: Bucket to create.
func (objectstoreClient *ObjectstoreClient) CreateBucket(bucket *Bucket) (*Bucket, error) {
	msg := C.RCString{}
	bucketJson, err := json.Marshal(bucket)
	if err != nil {
		return nil, err
	}
	cBucket := intoRCString(string(bucketJson))

	cBucketFn, errFn := C.objectstore_client_create_bucket(objectstoreClient.objectstoreClient, cBucket, &msg)
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
func (objectstoreClient *ObjectstoreClient) GetBucket(name string, namespace string) (*Bucket, error) {
	msg := C.RCString{}
	cName := intoRCString(name)
	cNamespace := intoRCString(namespace)

	cBucketFn, errFn := C.objectstore_client_get_bucket(objectstoreClient.objectstoreClient, cName, cNamespace, &msg)
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

// Deletes the specified bucket.
//
// name: Bucket name to be deleted. Cannot be empty.
// namespace: Namespace associated. Cannot be empty.
// emptyBucket: If true, the contents of the bucket will be emptied as part of the delete, otherwise it will fail if the bucket is not empty.
func (objectstoreClient *ObjectstoreClient) DeleteBucket(name string, namespace string, emptyBucket bool) error {
	msg := C.RCString{}
	cName := intoRCString(name)
	cNamespace := intoRCString(namespace)
	cEmptyBucket := cbool(emptyBucket)

	_, errFn := C.objectstore_client_delete_bucket(objectstoreClient.objectstoreClient, cName, cNamespace, cEmptyBucket, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Update an bucket.
//
// bucket: Bucket to update.
func (objectstoreClient *ObjectstoreClient) UpdateBucket(bucket *Bucket) (*Bucket, error) {
	msg := C.RCString{}
	bucketJson, err := json.Marshal(bucket)
	if err != nil {
		return nil, err
	}
	cBucket := intoRCString(string(bucketJson))

	cBucketFn, errFn := C.objectstore_client_update_bucket(objectstoreClient.objectstoreClient, cBucket, &msg)
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

// Gets the list of buckets for the specified namespace.
//
// namespace: Namespace for which buckets should be listed. Cannot be empty.
// name_prefix: Case sensitive prefix of the Bucket name with a wild card(*). Can be empty or any_prefix_string*.
func (objectstoreClient *ObjectstoreClient) ListBuckets(namespace string, namePrefix string) ([]Bucket, error) {
	msg := C.RCString{}
	cNamespace := intoRCString(namespace)
	cNamePrefix := intoRCString(namePrefix)

	cBucketsFn, errFn := C.objectstore_client_list_buckets(objectstoreClient.objectstoreClient, cNamespace, cNamePrefix, &msg)
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

// Creates the tenant which will associate an IAM Account within an objectstore.
//
// tenant: Tenant to create
func (objectstoreClient *ObjectstoreClient) CreateTenant(tenant *Tenant) (*Tenant, error) {
	msg := C.RCString{}
	tenantJson, err := json.Marshal(tenant)
	if err != nil {
		return nil, err
	}
	cTenant := intoRCString(string(tenantJson))

	cTenantFn, errFn := C.objectstore_client_create_tenant(objectstoreClient.objectstoreClient, cTenant, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	tenantYamlFn := fromRCString(cTenantFn)
	var tenantFn Tenant
	errUnmarshal := yaml.Unmarshal([]byte(tenantYamlFn), &tenantFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &tenantFn, nil
}

// Get the tenant.
//
// name: The associated account id. Cannot be empty.
func (objectstoreClient *ObjectstoreClient) GetTenant(name string) (*Tenant, error) {
	msg := C.RCString{}
	cName := intoRCString(name)

	cTenantFn, errFn := C.objectstore_client_get_tenant(objectstoreClient.objectstoreClient, cName, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	tenantYamlFn := fromRCString(cTenantFn)
	var tenantFn Tenant
	errUnmarshal := yaml.Unmarshal([]byte(tenantYamlFn), &tenantFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &tenantFn, nil
}

// Updates Tenant details like default_bucket_size and alias.
//
// tenant: Tenant to update
func (objectstoreClient *ObjectstoreClient) UpdateTenant(tenant *Tenant) (*Tenant, error) {
	msg := C.RCString{}
	tenantJson, err := json.Marshal(tenant)
	if err != nil {
		return nil, err
	}
	cTenant := intoRCString(string(tenantJson))

	cTenantFn, errFn := C.objectstore_client_update_tenant(objectstoreClient.objectstoreClient, cTenant, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	tenantYamlFn := fromRCString(cTenantFn)
	var tenantFn Tenant
	errUnmarshal := yaml.Unmarshal([]byte(tenantYamlFn), &tenantFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &tenantFn, nil
}

// Delete the tenant from an object store. Tenant must not own any buckets.
//
// name: The associated account id. Cannot be empty.
func (objectstoreClient *ObjectstoreClient) DeleteTenant(name string) error {
	msg := C.RCString{}
	cName := intoRCString(name)

	_, errFn := C.objectstore_client_delete_tenant(objectstoreClient.objectstoreClient, cName, &msg)
	if errFn != nil {
		return errorWithMessage(errFn, msg)
	}
	return nil

}

// Get the list of tenants.
//
// name_prefix: Case sensitive prefix of the tenant name with a wild card(*). Can be empty or any_prefix_string*.
func (objectstoreClient *ObjectstoreClient) ListTenants(namePrefix string) ([]Tenant, error) {
	msg := C.RCString{}
	cNamePrefix := intoRCString(namePrefix)

	cTenantsFn, errFn := C.objectstore_client_list_tenants(objectstoreClient.objectstoreClient, cNamePrefix, &msg)
	if errFn != nil {
		return nil, errorWithMessage(errFn, msg)
	}
	tenantsYamlFn := fromRCString(cTenantsFn)
	var tenantsFn []Tenant
	errUnmarshal := yaml.Unmarshal([]byte(tenantsYamlFn), &tenantsFn)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return tenantsFn, nil
}

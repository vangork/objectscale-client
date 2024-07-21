package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func TestAccount(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	name := "testaccount"
	description := "testaccount description"
	account := &objectscale.Account{
		Alias:             name,
		Description:       description,
		EncryptionEnabled: true,
		Tags:              []objectscale.Tag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}

	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	account, err = client.GetAccount(account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, name, account.Alias)
	assert.Equal(t, description, account.Description)
	assert.Equal(t, true, account.EncryptionEnabled)
	assert.Equal(t, 2, len(account.Tags))

	newName := "newtestaccount"
	newDescription := "newtestaccount description"
	account.Alias = newName
	account.Description = newDescription
	account, err = client.UpdateAccount(account)
	assert.Nil(t, err)
	assert.Equal(t, newName, account.Alias)
	assert.Equal(t, newDescription, account.Description)
	assert.Equal(t, true, account.EncryptionEnabled)
	assert.Equal(t, 2, len(account.Tags))

	accounts, err := client.ListAccounts()
	assert.Nil(t, err)
	assert.Less(t, 0, len(accounts))

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestUser(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountName := "testuseraccount"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	userName := "testuser"
	arn := "urn:osc:iam:::policy/CRRFullAccess"
	user := &objectscale.User{
		UserName:  userName,
		Namespace: account.AccountId,
		PermissionsBoundary: objectscale.PermissionsBoundary{
			PermissionsBoundaryArn: arn,
		},
		Tags: []objectscale.Tag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}
	_, err = client.CreateUser(user)
	assert.Nil(t, err)
	user, err = client.GetUser(userName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, userName, user.UserName)
	assert.Equal(t, account.AccountId, user.Namespace)
	assert.Equal(t, arn, user.PermissionsBoundary.PermissionsBoundaryArn)
	assert.Equal(t, 2, len(user.Tags))

	users, err := client.ListUsers(account.AccountId)
	assert.Nil(t, err)
	assert.Less(t, 0, len(users))

	err = client.DeleteUser(userName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestGroup(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountName := "testgroupaccount"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	groupName := "testgroup"
	group := &objectscale.Group{
		GroupName: groupName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateGroup(group)
	assert.Nil(t, err)

	group, err = client.GetGroup(groupName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, groupName, group.GroupName)
	assert.Equal(t, account.AccountId, group.Namespace)

	groups, err := client.ListGroups(account.AccountId)
	assert.Nil(t, err)
	assert.Less(t, 0, len(groups))

	err = client.DeleteGroup(groupName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestRole(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountName := "testroleaccount"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	roleName := "testrole"
	roleDescription := "testrole description"
	duration := int32(9600)
	assume_doc := `{"Version":"2024-07-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:osc:iam::osai0a9250592a131336:user/luis"]},"Action":"sts:AssumeRole"}]}`
	arn := "urn:osc:iam:::policy/CRRFullAccess"
	role := &objectscale.Role{
		RoleName:                 roleName,
		Description:              roleDescription,
		MaxSessionDuration:       duration,
		AssumeRolePolicyDocument: assume_doc,
		Namespace:                account.AccountId,
		PermissionsBoundary: objectscale.PermissionsBoundary{
			PermissionsBoundaryArn: arn,
		},
		Tags: []objectscale.Tag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}
	_, err = client.CreateRole(role)
	assert.Nil(t, err)

	role, err = client.GetRole(roleName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, roleName, role.RoleName)
	assert.Equal(t, roleDescription, role.Description)
	assert.Equal(t, duration, role.MaxSessionDuration)
	assert.Equal(t, account.AccountId, role.Namespace)
	assert.Equal(t, arn, role.PermissionsBoundary.PermissionsBoundaryArn)
	assert.Equal(t, 2, len(role.Tags))

	newRoleDescription := "newtestrole description"
	newDuration := int32(7200)
	role.Description = newRoleDescription
	role.MaxSessionDuration = newDuration
	role, err = client.UpdateRole(role)
	assert.Nil(t, err)
	assert.Equal(t, roleName, role.RoleName)
	assert.Equal(t, newRoleDescription, role.Description)
	assert.Equal(t, newDuration, role.MaxSessionDuration)
	assert.Equal(t, account.AccountId, role.Namespace)
	assert.Equal(t, arn, role.PermissionsBoundary.PermissionsBoundaryArn)
	assert.Equal(t, 2, len(role.Tags))

	roles, err := client.ListRoles(account.AccountId)
	assert.Nil(t, err)
	assert.Less(t, 0, len(roles))

	err = client.DeleteRole(roleName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestPolicy(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountName := "testpolicyaccount"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	document := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Action%22%3A%5B%22s3%3AListBucket%22%2C%22s3%3AListAllMyBuckets%22%5D%2C%22Resource%22%3A%22*%22%2C%22Effect%22%3A%22Allow%22%2C%22Sid%22%3A%22VisualEditor0%22%7D%5D%7D"
	policyName := "testpolicy"
	policyDescription := "testpolicy description"
	policy := &objectscale.Policy{
		PolicyName:     policyName,
		Description:    policyDescription,
		PolicyDocument: document,
		Namespace:      account.AccountId,
	}
	policy, err = client.CreatePolicy(policy)
	assert.Nil(t, err)

	policy, err = client.GetPolicy(policy.Arn, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, policyName, policy.PolicyName)
	assert.Equal(t, policyDescription, policy.Description)
	assert.Equal(t, account.AccountId, policy.Namespace)

	policies, err := client.ListPolicies(account.AccountId)
	assert.Nil(t, err)
	assert.Less(t, 0, len(policies))

	err = client.DeletePolicy(policy.Arn, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestUserGroupMembership(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountName := "testusergroupmembershipaccount"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	groupName := "testgroup"
	group := &objectscale.Group{
		GroupName: groupName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateGroup(group)
	assert.Nil(t, err)

	userName := "testuser"
	user := &objectscale.User{
		UserName:  userName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateUser(user)
	assert.Nil(t, err)

	memberShip := &objectscale.UserGroupMembership{
		UserName:  userName,
		GroupName: groupName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateUserGroupMembership(memberShip)
	assert.Nil(t, err)

	memberShips, err := client.ListUserGroupMembershipsByUser(userName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(memberShips))
	assert.Equal(t, groupName, memberShips[0].GroupName)
	assert.Equal(t, userName, memberShips[0].UserName)
	assert.Equal(t, account.AccountId, memberShips[0].Namespace)

	memberShips, err = client.ListUserGroupMembershipsByGroup(groupName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(memberShips))
	assert.Equal(t, groupName, memberShips[0].GroupName)
	assert.Equal(t, userName, memberShips[0].UserName)
	assert.Equal(t, account.AccountId, memberShips[0].Namespace)

	err = client.DeleteUserGroupMembership(memberShip)
	assert.Nil(t, err)

	err = client.DeleteUser(userName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteGroup(groupName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestGroupPolicyAttachment(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountName := "testgrouppolicyattachmentaccount"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	groupName := "testgroup"
	group := &objectscale.Group{
		GroupName: groupName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateGroup(group)
	assert.Nil(t, err)

	policyArn := "urn:osc:iam:::policy/CRRFullAccess"
	groupPolicyAttachment := &objectscale.GroupPolicyAttachment{
		GroupName: groupName,
		PolicyArn: policyArn,
		Namespace: account.AccountId,
	}

	_, err = client.CreateGroupPolicyAttachment(groupPolicyAttachment)
	assert.Nil(t, err)

	attachments, err := client.ListGroupPolicyAttachments(groupName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(attachments))
	assert.Equal(t, groupName, attachments[0].GroupName)
	assert.Equal(t, policyArn, attachments[0].PolicyArn)
	assert.Equal(t, account.AccountId, attachments[0].Namespace)

	err = client.DeleteGroupPolicyAttachment(groupPolicyAttachment)
	assert.Nil(t, err)

	attachments, err = client.ListGroupPolicyAttachments(groupName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(attachments))

	err = client.DeleteGroup(groupName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestUserPolicyAttachment(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountName := "testuserpolicyattachmentaccount"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	userName := "testuser"
	user := &objectscale.User{
		UserName:  userName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateUser(user)
	assert.Nil(t, err)

	policyArn := "urn:osc:iam:::policy/CRRFullAccess"
	userPolicyAttachment := &objectscale.UserPolicyAttachment{
		UserName:  userName,
		PolicyArn: policyArn,
		Namespace: account.AccountId,
	}
	_, err = client.CreateUserPolicyAttachment(userPolicyAttachment)
	assert.Nil(t, err)

	attachments, err := client.ListUserPolicyAttachments(userName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(attachments))
	assert.Equal(t, userName, attachments[0].UserName)
	assert.Equal(t, policyArn, attachments[0].PolicyArn)
	assert.Equal(t, account.AccountId, attachments[0].Namespace)

	err = client.DeleteUserPolicyAttachment(userPolicyAttachment)
	assert.Nil(t, err)

	attachments, err = client.ListUserPolicyAttachments(userName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(attachments))

	err = client.DeleteUser(userName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestRolePolicyAttachment(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountName := "testrolepolicyattachmentaccount"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	roleName := "testrole"
	assume_doc := `{"Version":"2024-07-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:osc:iam::osai0a9250592a131336:user/luis"]},"Action":"sts:AssumeRole"}]}`
	role := &objectscale.Role{
		RoleName:                 roleName,
		AssumeRolePolicyDocument: assume_doc,
		Namespace:                account.AccountId,
	}
	_, err = client.CreateRole(role)
	assert.Nil(t, err)

	policyArn := "urn:osc:iam:::policy/CRRFullAccess"
	rolePolicyAttachment := &objectscale.RolePolicyAttachment{
		RoleName:  roleName,
		PolicyArn: policyArn,
		Namespace: account.AccountId,
	}
	_, err = client.CreateRolePolicyAttachment(rolePolicyAttachment)
	assert.Nil(t, err)

	attachments, err := client.ListRolePolicyAttachments(roleName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(attachments))
	assert.Equal(t, roleName, attachments[0].RoleName)
	assert.Equal(t, policyArn, attachments[0].PolicyArn)
	assert.Equal(t, account.AccountId, attachments[0].Namespace)

	err = client.DeleteRolePolicyAttachment(rolePolicyAttachment)
	assert.Nil(t, err)

	attachments, err = client.ListRolePolicyAttachments(roleName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(attachments))

	err = client.DeleteRole(roleName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestEntitiesForPolicy(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountName := "testentitiesforpolicyaccount"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	groupName := "testgroup"
	group := &objectscale.Group{
		GroupName: groupName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateGroup(group)
	assert.Nil(t, err)

	userName := "testuser"
	user := &objectscale.User{
		UserName:  userName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateUser(user)
	assert.Nil(t, err)

	roleName := "testrole"
	assume_doc := `{"Version":"2024-07-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:osc:iam::osai0a9250592a131336:user/luis"]},"Action":"sts:AssumeRole"}]}`
	role := &objectscale.Role{
		RoleName:                 roleName,
		AssumeRolePolicyDocument: assume_doc,
		Namespace:                account.AccountId,
	}
	_, err = client.CreateRole(role)
	assert.Nil(t, err)

	document := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Action%22%3A%5B%22s3%3AListBucket%22%2C%22s3%3AListAllMyBuckets%22%5D%2C%22Resource%22%3A%22*%22%2C%22Effect%22%3A%22Allow%22%2C%22Sid%22%3A%22VisualEditor0%22%7D%5D%7D"
	policyName := "testpolicy"
	policy := &objectscale.Policy{
		PolicyName:     policyName,
		PolicyDocument: document,
		Namespace:      account.AccountId,
	}
	policy, err = client.CreatePolicy(policy)
	assert.Nil(t, err)

	groupPolicyAttachment := &objectscale.GroupPolicyAttachment{
		GroupName: groupName,
		PolicyArn: policy.Arn,
		Namespace: account.AccountId,
	}
	_, err = client.CreateGroupPolicyAttachment(groupPolicyAttachment)
	assert.Nil(t, err)

	userPolicyAttachment := &objectscale.UserPolicyAttachment{
		UserName:  userName,
		PolicyArn: policy.Arn,
		Namespace: account.AccountId,
	}
	_, err = client.CreateUserPolicyAttachment(userPolicyAttachment)
	assert.Nil(t, err)

	rolePolicyAttachment := &objectscale.RolePolicyAttachment{
		RoleName:  roleName,
		PolicyArn: policy.Arn,
		Namespace: account.AccountId,
	}
	_, err = client.CreateRolePolicyAttachment(rolePolicyAttachment)
	assert.Nil(t, err)

	entitiesForPolicy, err := client.GetEntitiesForPolicy(policy.Arn, account.AccountId, "", "")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(entitiesForPolicy.Groups))
	assert.Equal(t, 1, len(entitiesForPolicy.Users))
	assert.Equal(t, 1, len(entitiesForPolicy.Roles))
	assert.Equal(t, groupName, entitiesForPolicy.Groups[0])
	assert.Equal(t, userName, entitiesForPolicy.Users[0])
	assert.Equal(t, roleName, entitiesForPolicy.Roles[0])

	err = client.DeleteGroupPolicyAttachment(groupPolicyAttachment)
	assert.Nil(t, err)

	err = client.DeleteUserPolicyAttachment(userPolicyAttachment)
	assert.Nil(t, err)

	err = client.DeleteRolePolicyAttachment(rolePolicyAttachment)
	assert.Nil(t, err)

	err = client.DeleteRole(roleName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteUser(userName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteGroup(groupName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeletePolicy(policy.Arn, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestAccountAccessKey(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountname := "testaccountaccesskey"
	account := &objectscale.Account{
		Alias:             accountname,
		Description:       accountname,
		EncryptionEnabled: false,
	}

	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	accountAccessKey := &objectscale.AccountAccessKey{
		AccountId: account.AccountId,
	}

	accountAccessKey, err = client.CreateAccountAccessKey(accountAccessKey)
	assert.Nil(t, err)
	assert.NotEmpty(t, accountAccessKey.AccessKeyId)
	assert.NotEmpty(t, accountAccessKey.SecretAccessKey)
	assert.Equal(t, account.AccountId, accountAccessKey.AccountId)
	assert.Equal(t, "Active", accountAccessKey.Status)

	accountAccessKeys, err := client.ListAccountAccessKeys(account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(accountAccessKeys))
	assert.Equal(t, accountAccessKey.AccessKeyId, accountAccessKeys[0].AccessKeyId)

	accountAccessKey.Status = "Inactive"
	accountAccessKey, err = client.UpdateAccountAccessKey(accountAccessKey)
	assert.Nil(t, err)
	assert.NotEmpty(t, accountAccessKey.AccessKeyId)
	assert.Empty(t, accountAccessKey.SecretAccessKey)
	assert.Equal(t, account.AccountId, accountAccessKey.AccountId)
	assert.Equal(t, "Inactive", accountAccessKey.Status)

	err = client.DeleteAccountAccessKey(accountAccessKey.AccessKeyId, account.AccountId)
	assert.Nil(t, err)

	accountAccessKeys, err = client.ListAccountAccessKeys(account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(accountAccessKeys))

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestAccessKey(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountname := "testaccesskey"
	account := &objectscale.Account{
		Alias:             accountname,
		Description:       accountname,
		EncryptionEnabled: false,
	}

	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	userName := "testuser"
	user := &objectscale.User{
		UserName:  userName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateUser(user)
	assert.Nil(t, err)

	accessKey := &objectscale.AccessKey{
		UserName:  userName,
		Namespace: account.AccountId,
	}

	accessKey, err = client.CreateAccessKey(accessKey)
	assert.Nil(t, err)
	assert.NotEmpty(t, accessKey.AccessKeyId)
	assert.NotEmpty(t, accessKey.SecretAccessKey)
	assert.Equal(t, userName, accessKey.UserName)
	assert.Equal(t, account.AccountId, accessKey.Namespace)
	assert.Equal(t, "Active", accessKey.Status)

	accessKeys, err := client.ListAccessKeys(userName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(accessKeys))
	assert.Equal(t, userName, accessKeys[0].UserName)
	assert.Equal(t, accessKey.AccessKeyId, accessKeys[0].AccessKeyId)
	assert.Equal(t, account.AccountId, accessKeys[0].Namespace)
	assert.Equal(t, "Active", accessKeys[0].Status)

	accessKey.Status = "Inactive"
	accessKey, err = client.UpdateAccessKey(accessKey)
	assert.Nil(t, err)
	assert.NotEmpty(t, accessKey.AccessKeyId)
	assert.Empty(t, accessKey.SecretAccessKey)
	assert.Equal(t, userName, accessKey.UserName)
	assert.Equal(t, account.AccountId, accessKey.Namespace)
	assert.Equal(t, "Inactive", accessKey.Status)

	err = client.DeleteAccessKey(accessKey.AccessKeyId, userName, account.AccountId)
	assert.Nil(t, err)

	accessKeys, err = client.ListAccessKeys(userName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(accessKeys))

	err = client.DeleteUser(userName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestLoginProfile(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	accountname := "testloginprofile"
	account := &objectscale.Account{
		Alias:             accountname,
		Description:       accountname,
		EncryptionEnabled: false,
	}

	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	userName := "testuser"
	user := &objectscale.User{
		UserName:  userName,
		Namespace: account.AccountId,
	}
	_, err = client.CreateUser(user)
	assert.Nil(t, err)

	userPassword := "testpassword"
	resetRequired := false
	loginProfile := &objectscale.LoginProfile{
		UserName:              userName,
		Password:              userPassword,
		PasswordResetRequired: resetRequired,
		Namespace:             account.AccountId,
	}

	loginProfile, err = client.CreateLoginProfile(loginProfile)
	assert.Nil(t, err)
	assert.Empty(t, loginProfile.Password)
	assert.Equal(t, userName, loginProfile.UserName)
	assert.Equal(t, account.AccountId, loginProfile.Namespace)
	assert.Equal(t, resetRequired, loginProfile.PasswordResetRequired)

	loginProfile, err = client.GetLoginProfile(userName, account.AccountId)
	assert.Nil(t, err)
	assert.Empty(t, loginProfile.Password)
	assert.Equal(t, userName, loginProfile.UserName)
	assert.Equal(t, account.AccountId, loginProfile.Namespace)
	assert.Equal(t, resetRequired, loginProfile.PasswordResetRequired)

	err = client.DeleteLoginProfile(userName, account.AccountId)
	assert.Nil(t, err)

	_, err = client.GetLoginProfile(userName, account.AccountId)
	assert.NotNil(t, err)

	err = client.DeleteUser(userName, account.AccountId)
	assert.Nil(t, err)

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

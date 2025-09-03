package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func TestUser(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	namespaceName := "iam_test_user"
	namespace := &objectscale.Namespace{
		Name:                     namespaceName,
		DefaultDataServicesVpool: REPLICATION_GROUP,

		DefaultBucketBlockSize:  -1,
		NotificationSize:        -1,
		BlockSize:               -1,
		NotificationSizeInCount: -1,
		BlockSizeInCount:        -1,

		RetentionClasses: objectscale.RetentionClasses{
			RetentionClass: []objectscale.RetentionClass{},
		},
		UserMapping:          []objectscale.UserMapping{},
		AllowedVpoolsList:    []string{},
		DisallowedVpoolsList: []string{},
	}
	_, err := client.CreateNamespace(namespace)
	assert.Nil(t, err)

	userName := "iam_test_user"
	arn := "urn:ecs:iam:::policy/ECSS3FullAccess"
	user := &objectscale.User{
		UserName:  userName,
		Namespace: namespaceName,
		Tags:      []objectscale.IamTag{},
	}
	user, err = client.CreateUser(user)
	assert.Nil(t, err)
	assert.Equal(t, userName, user.UserName)
	assert.Equal(t, namespaceName, user.Namespace)
	assert.Equal(t, 0, len(user.Tags))

	user.Tags = []objectscale.IamTag{
		{Key: "key1", Value: "value1"},
	}
	user.PermissionsBoundary = objectscale.PermissionsBoundary{
		PermissionsBoundaryArn:  arn,
		PermissionsBoundaryType: "",
	}

	state, err := client.UpdateUser(user)
	assert.Nil(t, err)
	assert.Equal(t, true, state)

	user, err = client.GetUser(userName, namespaceName)
	assert.Nil(t, err)
	assert.Equal(t, userName, user.UserName)
	assert.Equal(t, namespaceName, user.Namespace)
	assert.Equal(t, 1, len(user.Tags))
	assert.Equal(t, arn, user.PermissionsBoundary.PermissionsBoundaryArn)

	users, err := client.ListUsers(namespaceName)
	assert.Nil(t, err)
	assert.Less(t, 0, len(users))

	err = client.DeleteUser(userName, namespaceName)
	assert.Nil(t, err)

	err = client.DeleteNamespace(namespaceName)
	assert.Nil(t, err)
}

func TestUserPolicyAttachment(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	namespaceName := "iam_test_user_policy_attachment"
	namespace := &objectscale.Namespace{
		Name:                     namespaceName,
		DefaultDataServicesVpool: REPLICATION_GROUP,

		DefaultBucketBlockSize:  -1,
		NotificationSize:        -1,
		BlockSize:               -1,
		NotificationSizeInCount: -1,
		BlockSizeInCount:        -1,

		RetentionClasses: objectscale.RetentionClasses{
			RetentionClass: []objectscale.RetentionClass{},
		},
		UserMapping:          []objectscale.UserMapping{},
		AllowedVpoolsList:    []string{},
		DisallowedVpoolsList: []string{},
	}
	_, err := client.CreateNamespace(namespace)
	assert.Nil(t, err)

	userName := "iam_test_user_policy_attachment"
	user := &objectscale.User{
		UserName:  userName,
		Namespace: namespaceName,
		Tags:      []objectscale.IamTag{},
	}
	_, err = client.CreateUser(user)
	assert.Nil(t, err)

	policyArn := "urn:ecs:iam:::policy/ECSS3FullAccess"
	userPolicyAttachment := &objectscale.UserPolicyAttachment{
		UserName:  userName,
		PolicyArn: policyArn,
		Namespace: namespaceName,
	}
	attachment, err := client.CreateUserPolicyAttachment(userPolicyAttachment)
	assert.Nil(t, err)
	assert.Equal(t, userName, attachment.UserName)
	assert.Equal(t, policyArn, attachment.PolicyArn)
	assert.Equal(t, namespaceName, attachment.Namespace)

	attachments, err := client.ListUserPolicyAttachments(userName, namespaceName)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(attachments))
	assert.Equal(t, userName, attachments[0].UserName)
	assert.Equal(t, policyArn, attachments[0].PolicyArn)
	assert.Equal(t, namespaceName, attachments[0].Namespace)

	err = client.DeleteUserPolicyAttachment(userPolicyAttachment)
	assert.Nil(t, err)

	attachments, err = client.ListUserPolicyAttachments(userName, namespaceName)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(attachments))

	err = client.DeleteUser(userName, namespaceName)
	assert.Nil(t, err)

	err = client.DeleteNamespace(namespaceName)
	assert.Nil(t, err)
}

func TestAccessKey(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	namespaceName := "iam_test_access_key"
	namespace := &objectscale.Namespace{
		Name:                     namespaceName,
		DefaultDataServicesVpool: REPLICATION_GROUP,

		DefaultBucketBlockSize:  -1,
		NotificationSize:        -1,
		BlockSize:               -1,
		NotificationSizeInCount: -1,
		BlockSizeInCount:        -1,

		RetentionClasses: objectscale.RetentionClasses{
			RetentionClass: []objectscale.RetentionClass{},
		},
		UserMapping:          []objectscale.UserMapping{},
		AllowedVpoolsList:    []string{},
		DisallowedVpoolsList: []string{},
	}
	_, err := client.CreateNamespace(namespace)
	assert.Nil(t, err)

	userName := "iam_test_access_key"
	user := &objectscale.User{
		UserName:  userName,
		Namespace: namespaceName,
		Tags:      []objectscale.IamTag{},
	}
	_, err = client.CreateUser(user)
	assert.Nil(t, err)

	accessKey := &objectscale.AccessKey{
		UserName:  userName,
		Namespace: namespaceName,
	}

	accessKey, err = client.CreateAccessKey(accessKey)
	assert.Nil(t, err)
	assert.NotEmpty(t, accessKey.AccessKeyId)
	assert.NotEmpty(t, accessKey.SecretAccessKey)
	assert.Equal(t, userName, accessKey.UserName)
	assert.Equal(t, namespaceName, accessKey.Namespace)
	assert.Equal(t, "Active", accessKey.Status)

	accessKey.Status = "Inactive"
	state, err := client.UpdateAccessKey(accessKey)
	assert.Nil(t, err)
	assert.Equal(t, true, state)

	accessKeys, err := client.ListAccessKeys(userName, namespaceName)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(accessKeys))
	assert.Equal(t, userName, accessKeys[0].UserName)
	assert.Equal(t, accessKey.AccessKeyId, accessKeys[0].AccessKeyId)
	assert.Equal(t, namespaceName, accessKeys[0].Namespace)
	assert.Equal(t, "Inactive", accessKeys[0].Status)

	err = client.DeleteAccessKey(accessKey.AccessKeyId, userName, namespaceName)
	assert.Nil(t, err)

	accessKeys, err = client.ListAccessKeys(userName, namespaceName)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(accessKeys))

	err = client.DeleteUser(userName, namespaceName)
	assert.Nil(t, err)

	err = client.DeleteNamespace(namespaceName)
	assert.Nil(t, err)
}

func TestPolicy(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	namespaceName := "iam_test_access_key"
	namespace := &objectscale.Namespace{
		Name:                     namespaceName,
		DefaultDataServicesVpool: REPLICATION_GROUP,

		DefaultBucketBlockSize:  -1,
		NotificationSize:        -1,
		BlockSize:               -1,
		NotificationSizeInCount: -1,
		BlockSizeInCount:        -1,

		RetentionClasses: objectscale.RetentionClasses{
			RetentionClass: []objectscale.RetentionClass{},
		},
		UserMapping:          []objectscale.UserMapping{},
		AllowedVpoolsList:    []string{},
		DisallowedVpoolsList: []string{},
	}
	_, err := client.CreateNamespace(namespace)
	assert.Nil(t, err)

	document := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Action%22%3A%5B%22s3%3AListBucket%22%2C%22s3%3AListAllMyBuckets%22%5D%2C%22Resource%22%3A%22*%22%2C%22Effect%22%3A%22Allow%22%2C%22Sid%22%3A%22VisualEditor0%22%7D%5D%7D"
	policyName := "iam_test_policy"
	policyDescription := "testpolicy description"
	policy := &objectscale.Policy{
		PolicyName:     policyName,
		Description:    policyDescription,
		PolicyDocument: document,
		Namespace:      namespaceName,
	}
	policy, err = client.CreatePolicy(policy)
	assert.Nil(t, err)
	assert.Equal(t, policyName, policy.PolicyName)
	assert.Equal(t, policyDescription, policy.Description)
	assert.Equal(t, namespaceName, policy.Namespace)

	policy, err = client.GetPolicy(policy.Arn, namespaceName)
	assert.Nil(t, err)
	assert.Equal(t, policyName, policy.PolicyName)
	assert.Equal(t, policyDescription, policy.Description)
	assert.Equal(t, namespaceName, policy.Namespace)

	policies, err := client.ListPolicies(namespaceName)
	assert.Nil(t, err)
	assert.Less(t, 0, len(policies))

	err = client.DeletePolicy(policy.Arn, namespaceName)
	assert.Nil(t, err)

	err = client.DeleteNamespace(namespaceName)
	assert.Nil(t, err)
}

func TestGroup(t *testing.T) {
	client := CreateManagementClient(t)
	defer client.Close()

	namespaceName := "iam_test_access_key"
	namespace := &objectscale.Namespace{
		Name:                     namespaceName,
		DefaultDataServicesVpool: REPLICATION_GROUP,

		DefaultBucketBlockSize:  -1,
		NotificationSize:        -1,
		BlockSize:               -1,
		NotificationSizeInCount: -1,
		BlockSizeInCount:        -1,

		RetentionClasses: objectscale.RetentionClasses{
			RetentionClass: []objectscale.RetentionClass{},
		},
		UserMapping:          []objectscale.UserMapping{},
		AllowedVpoolsList:    []string{},
		DisallowedVpoolsList: []string{},
	}
	_, err := client.CreateNamespace(namespace)
	assert.Nil(t, err)

	groupName := "iam_test_group"
	group := &objectscale.Group{
		GroupName: groupName,
		Namespace: namespaceName,
	}
	group, err = client.CreateGroup(group)
	assert.Nil(t, err)
	assert.Equal(t, groupName, group.GroupName)
	assert.Equal(t, namespaceName, group.Namespace)

	group, err = client.GetGroup(groupName, namespaceName)
	assert.Nil(t, err)
	assert.Equal(t, groupName, group.GroupName)
	assert.Equal(t, namespaceName, group.Namespace)

	groups, err := client.ListGroups(namespaceName)
	assert.Nil(t, err)
	assert.Less(t, 0, len(groups))

	err = client.DeleteGroup(groupName, namespaceName)
	assert.Nil(t, err)

	err = client.DeleteNamespace(namespaceName)
	assert.Nil(t, err)
}

// func TestRole(t *testing.T) {
// 	client := CreateManagementClient(t)
// 	defer client.Close()

// 	accountName := "testroleaccount"
// 	account := &objectscale.Account{
// 		Alias:             accountName,
// 		Description:       accountName,
// 		EncryptionEnabled: false,
// 	}
// 	account, err := client.CreateAccount(account)
// 	assert.Nil(t, err)

// 	roleName := "testrole"
// 	roleDescription := "testrole description"
// 	duration := int32(9600)
// 	assume_doc := `{"Version":"2024-07-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:osc:iam::osai0a9250592a131336:user/luis"]},"Action":"sts:AssumeRole"}]}`
// 	arn := "urn:osc:iam:::policy/CRRFullAccess"
// 	role := &objectscale.Role{
// 		RoleName:                 roleName,
// 		Description:              roleDescription,
// 		MaxSessionDuration:       duration,
// 		AssumeRolePolicyDocument: assume_doc,
// 		Namespace:                namespaceName,
// 		PermissionsBoundary: objectscale.PermissionsBoundary{
// 			PermissionsBoundaryArn: arn,
// 		},
// 		Tags: []objectscale.Tag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
// 	}
// 	_, err = client.CreateRole(role)
// 	assert.Nil(t, err)

// 	role, err = client.GetRole(roleName, namespaceName)
// 	assert.Nil(t, err)
// 	assert.Equal(t, roleName, role.RoleName)
// 	assert.Equal(t, roleDescription, role.Description)
// 	assert.Equal(t, duration, role.MaxSessionDuration)
// 	assert.Equal(t, namespaceName, role.Namespace)
// 	assert.Equal(t, arn, role.PermissionsBoundary.PermissionsBoundaryArn)
// 	assert.Equal(t, 2, len(role.Tags))

// 	newRoleDescription := "newtestrole description"
// 	newDuration := int32(7200)
// 	role.Description = newRoleDescription
// 	role.MaxSessionDuration = newDuration
// 	role, err = client.UpdateRole(role)
// 	assert.Nil(t, err)
// 	assert.Equal(t, roleName, role.RoleName)
// 	assert.Equal(t, newRoleDescription, role.Description)
// 	assert.Equal(t, newDuration, role.MaxSessionDuration)
// 	assert.Equal(t, namespaceName, role.Namespace)
// 	assert.Equal(t, arn, role.PermissionsBoundary.PermissionsBoundaryArn)
// 	assert.Equal(t, 2, len(role.Tags))

// 	roles, err := client.ListRoles(namespaceName)
// 	assert.Nil(t, err)
// 	assert.Less(t, 0, len(roles))

// 	err = client.DeleteRole(roleName, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeleteAccount(namespaceName)
// 	assert.Nil(t, err)
// }

// func TestUserGroupMembership(t *testing.T) {
// 	client := CreateManagementClient(t)
// 	defer client.Close()

// 	accountName := "testusergroupmembershipaccount"
// 	account := &objectscale.Account{
// 		Alias:             accountName,
// 		Description:       accountName,
// 		EncryptionEnabled: false,
// 	}
// 	account, err := client.CreateAccount(account)
// 	assert.Nil(t, err)

// 	groupName := "testgroup"
// 	group := &objectscale.Group{
// 		GroupName: groupName,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateGroup(group)
// 	assert.Nil(t, err)

// 	userName := "testuser"
// 	user := &objectscale.User{
// 		UserName:  userName,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateUser(user)
// 	assert.Nil(t, err)

// 	memberShip := &objectscale.UserGroupMembership{
// 		UserName:  userName,
// 		GroupName: groupName,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateUserGroupMembership(memberShip)
// 	assert.Nil(t, err)

// 	memberShips, err := client.ListUserGroupMembershipsByUser(userName, namespaceName)
// 	assert.Nil(t, err)
// 	assert.Equal(t, 1, len(memberShips))
// 	assert.Equal(t, groupName, memberShips[0].GroupName)
// 	assert.Equal(t, userName, memberShips[0].UserName)
// 	assert.Equal(t, namespaceName, memberShips[0].Namespace)

// 	memberShips, err = client.ListUserGroupMembershipsByGroup(groupName, namespaceName)
// 	assert.Nil(t, err)
// 	assert.Equal(t, 1, len(memberShips))
// 	assert.Equal(t, groupName, memberShips[0].GroupName)
// 	assert.Equal(t, userName, memberShips[0].UserName)
// 	assert.Equal(t, namespaceName, memberShips[0].Namespace)

// 	err = client.DeleteUserGroupMembership(memberShip)
// 	assert.Nil(t, err)

// 	err = client.DeleteUser(userName, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeleteGroup(groupName, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeleteAccount(namespaceName)
// 	assert.Nil(t, err)
// }

// func TestGroupPolicyAttachment(t *testing.T) {
// 	client := CreateManagementClient(t)
// 	defer client.Close()

// 	accountName := "testgrouppolicyattachmentaccount"
// 	account := &objectscale.Account{
// 		Alias:             accountName,
// 		Description:       accountName,
// 		EncryptionEnabled: false,
// 	}
// 	account, err := client.CreateAccount(account)
// 	assert.Nil(t, err)

// 	groupName := "testgroup"
// 	group := &objectscale.Group{
// 		GroupName: groupName,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateGroup(group)
// 	assert.Nil(t, err)

// 	policyArn := "urn:osc:iam:::policy/CRRFullAccess"
// 	groupPolicyAttachment := &objectscale.GroupPolicyAttachment{
// 		GroupName: groupName,
// 		PolicyArn: policyArn,
// 		Namespace: namespaceName,
// 	}

// 	_, err = client.CreateGroupPolicyAttachment(groupPolicyAttachment)
// 	assert.Nil(t, err)

// 	attachments, err := client.ListGroupPolicyAttachments(groupName, namespaceName)
// 	assert.Nil(t, err)
// 	assert.Equal(t, 1, len(attachments))
// 	assert.Equal(t, groupName, attachments[0].GroupName)
// 	assert.Equal(t, policyArn, attachments[0].PolicyArn)
// 	assert.Equal(t, namespaceName, attachments[0].Namespace)

// 	err = client.DeleteGroupPolicyAttachment(groupPolicyAttachment)
// 	assert.Nil(t, err)

// 	attachments, err = client.ListGroupPolicyAttachments(groupName, namespaceName)
// 	assert.Nil(t, err)
// 	assert.Equal(t, 0, len(attachments))

// 	err = client.DeleteGroup(groupName, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeleteAccount(namespaceName)
// 	assert.Nil(t, err)
// }

// func TestRolePolicyAttachment(t *testing.T) {
// 	client := CreateManagementClient(t)
// 	defer client.Close()

// 	accountName := "testrolepolicyattachmentaccount"
// 	account := &objectscale.Account{
// 		Alias:             accountName,
// 		Description:       accountName,
// 		EncryptionEnabled: false,
// 	}
// 	account, err := client.CreateAccount(account)
// 	assert.Nil(t, err)

// 	roleName := "testrole"
// 	assume_doc := `{"Version":"2024-07-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:osc:iam::osai0a9250592a131336:user/luis"]},"Action":"sts:AssumeRole"}]}`
// 	role := &objectscale.Role{
// 		RoleName:                 roleName,
// 		AssumeRolePolicyDocument: assume_doc,
// 		Namespace:                namespaceName,
// 	}
// 	_, err = client.CreateRole(role)
// 	assert.Nil(t, err)

// 	policyArn := "urn:osc:iam:::policy/CRRFullAccess"
// 	rolePolicyAttachment := &objectscale.RolePolicyAttachment{
// 		RoleName:  roleName,
// 		PolicyArn: policyArn,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateRolePolicyAttachment(rolePolicyAttachment)
// 	assert.Nil(t, err)

// 	attachments, err := client.ListRolePolicyAttachments(roleName, namespaceName)
// 	assert.Nil(t, err)
// 	assert.Equal(t, 1, len(attachments))
// 	assert.Equal(t, roleName, attachments[0].RoleName)
// 	assert.Equal(t, policyArn, attachments[0].PolicyArn)
// 	assert.Equal(t, namespaceName, attachments[0].Namespace)

// 	err = client.DeleteRolePolicyAttachment(rolePolicyAttachment)
// 	assert.Nil(t, err)

// 	attachments, err = client.ListRolePolicyAttachments(roleName, namespaceName)
// 	assert.Nil(t, err)
// 	assert.Equal(t, 0, len(attachments))

// 	err = client.DeleteRole(roleName, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeleteAccount(namespaceName)
// 	assert.Nil(t, err)
// }

// func TestEntitiesForPolicy(t *testing.T) {
// 	client := CreateManagementClient(t)
// 	defer client.Close()

// 	accountName := "testentitiesforpolicyaccount"
// 	account := &objectscale.Account{
// 		Alias:             accountName,
// 		Description:       accountName,
// 		EncryptionEnabled: false,
// 	}
// 	account, err := client.CreateAccount(account)
// 	assert.Nil(t, err)

// 	groupName := "testgroup"
// 	group := &objectscale.Group{
// 		GroupName: groupName,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateGroup(group)
// 	assert.Nil(t, err)

// 	userName := "testuser"
// 	user := &objectscale.User{
// 		UserName:  userName,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateUser(user)
// 	assert.Nil(t, err)

// 	roleName := "testrole"
// 	assume_doc := `{"Version":"2024-07-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:osc:iam::osai0a9250592a131336:user/luis"]},"Action":"sts:AssumeRole"}]}`
// 	role := &objectscale.Role{
// 		RoleName:                 roleName,
// 		AssumeRolePolicyDocument: assume_doc,
// 		Namespace:                namespaceName,
// 	}
// 	_, err = client.CreateRole(role)
// 	assert.Nil(t, err)

// 	document := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Action%22%3A%5B%22s3%3AListBucket%22%2C%22s3%3AListAllMyBuckets%22%5D%2C%22Resource%22%3A%22*%22%2C%22Effect%22%3A%22Allow%22%2C%22Sid%22%3A%22VisualEditor0%22%7D%5D%7D"
// 	policyName := "testpolicy"
// 	policy := &objectscale.Policy{
// 		PolicyName:     policyName,
// 		PolicyDocument: document,
// 		Namespace:      namespaceName,
// 	}
// 	policy, err = client.CreatePolicy(policy)
// 	assert.Nil(t, err)

// 	groupPolicyAttachment := &objectscale.GroupPolicyAttachment{
// 		GroupName: groupName,
// 		PolicyArn: policy.Arn,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateGroupPolicyAttachment(groupPolicyAttachment)
// 	assert.Nil(t, err)

// 	userPolicyAttachment := &objectscale.UserPolicyAttachment{
// 		UserName:  userName,
// 		PolicyArn: policy.Arn,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateUserPolicyAttachment(userPolicyAttachment)
// 	assert.Nil(t, err)

// 	rolePolicyAttachment := &objectscale.RolePolicyAttachment{
// 		RoleName:  roleName,
// 		PolicyArn: policy.Arn,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateRolePolicyAttachment(rolePolicyAttachment)
// 	assert.Nil(t, err)

// 	entitiesForPolicy, err := client.GetEntitiesForPolicy(policy.Arn, namespaceName, "", "")
// 	assert.Nil(t, err)
// 	assert.Equal(t, 1, len(entitiesForPolicy.Groups))
// 	assert.Equal(t, 1, len(entitiesForPolicy.Users))
// 	assert.Equal(t, 1, len(entitiesForPolicy.Roles))
// 	assert.Equal(t, groupName, entitiesForPolicy.Groups[0])
// 	assert.Equal(t, userName, entitiesForPolicy.Users[0])
// 	assert.Equal(t, roleName, entitiesForPolicy.Roles[0])

// 	err = client.DeleteGroupPolicyAttachment(groupPolicyAttachment)
// 	assert.Nil(t, err)

// 	err = client.DeleteUserPolicyAttachment(userPolicyAttachment)
// 	assert.Nil(t, err)

// 	err = client.DeleteRolePolicyAttachment(rolePolicyAttachment)
// 	assert.Nil(t, err)

// 	err = client.DeleteRole(roleName, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeleteUser(userName, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeleteGroup(groupName, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeletePolicy(policy.Arn, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeleteAccount(namespaceName)
// 	assert.Nil(t, err)
// }

// func TestLoginProfile(t *testing.T) {
// 	client := CreateManagementClient(t)
// 	defer client.Close()

// 	accountname := "testloginprofile"
// 	account := &objectscale.Account{
// 		Alias:             accountname,
// 		Description:       accountname,
// 		EncryptionEnabled: false,
// 	}

// 	account, err := client.CreateAccount(account)
// 	assert.Nil(t, err)

// 	userName := "testuser"
// 	user := &objectscale.User{
// 		UserName:  userName,
// 		Namespace: namespaceName,
// 	}
// 	_, err = client.CreateUser(user)
// 	assert.Nil(t, err)

// 	userPassword := "testpassword"
// 	resetRequired := false
// 	loginProfile := &objectscale.LoginProfile{
// 		UserName:              userName,
// 		Password:              userPassword,
// 		PasswordResetRequired: resetRequired,
// 		Namespace:             namespaceName,
// 	}

// 	loginProfile, err = client.CreateLoginProfile(loginProfile)
// 	assert.Nil(t, err)
// 	assert.Empty(t, loginProfile.Password)
// 	assert.Equal(t, userName, loginProfile.UserName)
// 	assert.Equal(t, namespaceName, loginProfile.Namespace)
// 	assert.Equal(t, resetRequired, loginProfile.PasswordResetRequired)

// 	loginProfile, err = client.GetLoginProfile(userName, namespaceName)
// 	assert.Nil(t, err)
// 	assert.Empty(t, loginProfile.Password)
// 	assert.Equal(t, userName, loginProfile.UserName)
// 	assert.Equal(t, namespaceName, loginProfile.Namespace)
// 	assert.Equal(t, resetRequired, loginProfile.PasswordResetRequired)

// 	err = client.DeleteLoginProfile(userName, namespaceName)
// 	assert.Nil(t, err)

// 	_, err = client.GetLoginProfile(userName, namespaceName)
// 	assert.NotNil(t, err)

// 	err = client.DeleteUser(userName, namespaceName)
// 	assert.Nil(t, err)

// 	err = client.DeleteAccount(namespaceName)
// 	assert.Nil(t, err)
// }

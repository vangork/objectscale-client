//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func TestManagementUser(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	name := "user_test_management_user"
	password := "Password123!"

	user := &objectscale.ManagementUser{
		UserId:   name,
		Password: password,
	}
	user, err := manamgentclient.CreateManagementUser(user)
	assert.Nil(t, err)
	assert.Equal(t, user.UserId, name)
	assert.Equal(t, false, user.IsLocked)
	assert.Equal(t, false, user.IsSecurityAdmin)

	user.IsSecurityAdmin = true
	user.IsSystemAdmin = true
	user.IsSystemMonitor = true
	state, err := manamgentclient.UpdateManagementUser(user)
	assert.Nil(t, err)
	assert.Equal(t, true, state)

	user, err = manamgentclient.GetManagementUser(name)
	assert.Nil(t, err)
	assert.Equal(t, true, user.IsSecurityAdmin)
	assert.Equal(t, true, user.IsSecurityAdmin)
	assert.Equal(t, true, user.IsSystemMonitor)

	users, err := manamgentclient.ListManagementUsers()
	assert.Nil(t, err)
	assert.Less(t, 0, len(users))

	err = manamgentclient.DeleteManagementUser(name)
	assert.Nil(t, err)
}

func TestObjectUser(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	namespaceName := "user_test_object_user"
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
	_, err := manamgentclient.CreateNamespace(namespace)
	assert.Nil(t, err)

	name := "user_test_object_user"
	user := &objectscale.ObjectUser{
		Name:      name,
		Namespace: namespaceName,
		Tag:       []objectscale.UserTag{},
		SwiftGroup: objectscale.SwiftGroup{
			GroupsList: []string{},
		},
		SecretKeys: []objectscale.SecretKey{},
	}
	user, err = manamgentclient.CreateObjectUser(user)
	assert.Nil(t, err)
	assert.Equal(t, name, user.Name)
	assert.Equal(t, namespaceName, user.Namespace)
	assert.Equal(t, false, user.Locked)
	assert.Equal(t, 0, len(user.Tag))
	assert.Equal(t, 0, len(user.SecretKeys))
	assert.Equal(t, false, user.SwiftGroup.SwiftPasswordConfigured)

	user.Tag = []objectscale.UserTag{
		{Name: "key1", Value: "value1"},
	}
	user.SwiftGroup.GroupsList = []string{"admin"}
	user.SwiftGroup.Password = "12345678"
	user.SecretKeys = []objectscale.SecretKey{
		{},
		{ExistingKeyExpiryTimeMins: "30"},
	}

	state, err := manamgentclient.UpdateObjectUser(user)
	assert.Nil(t, err)
	assert.Equal(t, true, state)

	user, err = manamgentclient.GetObjectUser(name, namespaceName)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(user.Tag))
	assert.Equal(t, 2, len(user.SecretKeys))
	assert.Equal(t, true, user.SwiftGroup.SwiftPasswordConfigured)

	users, err := manamgentclient.ListObjectUsers()
	assert.Nil(t, err)
	assert.Less(t, 0, len(users))

	err = manamgentclient.DeleteObjectUser(name, namespaceName)
	assert.Nil(t, err)

	err = manamgentclient.DeleteNamespace(namespaceName)
	assert.Nil(t, err)
}

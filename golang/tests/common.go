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
	objectscale "github.com/dell/objectscale-client/golang/pkg"
)

const REPLICATION_GROUP string = "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global"

func CreateManagementClient(t *testing.T) *objectscale.ManagementClient {
	endpoint := "https://10.225.108.217:4443"
	username := "root"
	password := "Password123!"
	insecure := true
	client, err := objectscale.NewManagementClient(endpoint, username, password, insecure)
	assert.Nil(t, err)
	return client
}

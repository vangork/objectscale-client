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

func TestBucket(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	namespaceName := "provisioning_test_bucket"
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

	bucketName := "provisioning_test_bucket"

	bucket := &objectscale.Bucket{
		Name:                    bucketName,
		Namespace:               namespaceName,
		BlockSize:               -1,
		NotificationSize:        -1,
		BlockSizeInCount:        -1,
		NotificationSizeInCount: -1,
		AuditDeleteExpiration:   -2,
		Tags:                    []objectscale.BucketTag{},
	}
	bucket, err = manamgentclient.CreateBucket(bucket)
	assert.Nil(t, err)
	assert.Equal(t, bucketName, bucket.Name)
	assert.Equal(t, namespaceName, bucket.Namespace)
	assert.Equal(t, 0, len(bucket.Tags))

	bucket.Tags = []objectscale.BucketTag{
		{Key: "key1", Value: "value1"},
	}

	state, err := manamgentclient.UpdateBucket(bucket)
	assert.Nil(t, err)
	assert.Equal(t, true, state)

	bucket, err = manamgentclient.GetBucket(bucketName, namespaceName)
	assert.Nil(t, err)
	assert.Equal(t, bucketName, bucket.Name)
	assert.Equal(t, namespaceName, bucket.Namespace)
	assert.Equal(t, 1, len(bucket.Tags))

	buckets, err := manamgentclient.ListBuckets(namespaceName, "")
	assert.Nil(t, err)
	assert.Less(t, 0, len(buckets))

	err = manamgentclient.DeleteBucket(bucketName, namespaceName, false)
	assert.Nil(t, err)

	err = manamgentclient.DeleteNamespace(namespaceName)
	assert.Nil(t, err)
}

func TestVdc(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	vdcName := "vdc1"
	vdc, err := manamgentclient.GetVdc(vdcName)
	assert.Nil(t, err)
	assert.Equal(t, vdcName, vdc.Name)

	vdcs, err := manamgentclient.ListVdcs()
	assert.Nil(t, err)
	assert.Less(t, 0, len(vdcs))
}

func TestVdcKeyStore(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	store, err := manamgentclient.GetVdcKeystore()
	assert.Nil(t, err)
	assert.NotEmpty(t, store.Chain)
}

func TestStoragePool(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	spId := "urn:storageos:VirtualArray:2a36f1a7-4281-453d-8927-788f8033416b"

	sp, err := manamgentclient.GetStoragePool(spId)
	assert.Nil(t, err)
	assert.Equal(t, spId, sp.Id)

	originalSp := &objectscale.StoragePool{
		Name:                 sp.Name,
		Id:                   sp.Id,
		Description:          sp.Description,
		WarningAlertAt:       sp.WarningAlertAt,
		ErrorAlertAt:         sp.ErrorAlertAt,
		CriticalAlertAt:      sp.CriticalAlertAt,
		IsProtected:          sp.IsProtected,
		IsColdStorageEnabled: sp.IsColdStorageEnabled,
		NumberOfDataBlocks:   sp.NumberOfDataBlocks,
		NumberOfCodeBlocks:   sp.NumberOfCodeBlocks,
		Label:                sp.Label,
		DriveTechnology:      sp.DriveTechnology,
		Status:               sp.Status,
	}

	sp.Name = "sp2"
	sp.Description = "sp2 description"
	sp.WarningAlertAt = 35
	sp.ErrorAlertAt = -1
	sp.CriticalAlertAt = -1

	state, err := manamgentclient.UpdateStoragePool(sp)
	assert.Nil(t, err)
	assert.Equal(t, true, state)

	sp, err = manamgentclient.GetStoragePool(spId)
	assert.Nil(t, err)
	assert.Equal(t, sp.Name, "sp2")
	assert.Equal(t, sp.Description, "sp2 description")
	assert.Equal(t, sp.WarningAlertAt, int64(35))
	assert.Equal(t, sp.ErrorAlertAt, int64(-1))
	assert.Equal(t, sp.CriticalAlertAt, int64(-1))

	_, err = manamgentclient.UpdateStoragePool(originalSp)
	assert.Nil(t, err)

	sps, err := manamgentclient.ListStoragePools()
	assert.Nil(t, err)
	assert.Less(t, 0, len(sps))
}

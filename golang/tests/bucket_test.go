package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func TestBucket(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	objectstoreClient := CreateObjectstoreClient(t)
	defer objectstoreClient.Close()

	accountName := "testbucket"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := manamgentclient.CreateAccount(account)
	assert.Nil(t, err)

	alias := "testbucket"
	encryptionEnabled := false
	tenant := &objectscale.Tenant{
		Alias:               alias,
		Id:                  account.AccountId,
		IsEncryptionEnabled: encryptionEnabled,
	}
	_, err = objectstoreClient.CreateTenant(tenant)
	assert.Nil(t, err)

	bucketName := "testbucket"
	expiration := int64(-1)
	bucket := &objectscale.Bucket{
		Name:                  bucketName,
		Namespace:             account.AccountId,
		AuditDeleteExpiration: expiration,
		Tags:                  []objectscale.BucketTag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}
	_, err = objectstoreClient.CreateBucket(bucket)
	assert.Nil(t, err)

	bucket, err = objectstoreClient.GetBucket(bucketName, account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, bucketName, bucket.Name)
	assert.Equal(t, account.AccountId, bucket.Namespace)
	assert.Equal(t, 2, len(bucket.Tags))
	assert.Equal(t, expiration, bucket.AuditDeleteExpiration)

	newExpiration := int64(0)
	bucket.AuditDeleteExpiration = newExpiration
	bucket, err = objectstoreClient.UpdateBucket(bucket)
	assert.Nil(t, err)
	assert.Equal(t, newExpiration, bucket.AuditDeleteExpiration)
	assert.Equal(t, bucketName, bucket.Name)
	assert.Equal(t, account.AccountId, bucket.Namespace)
	assert.Equal(t, 2, len(bucket.Tags))

	buckets, err := objectstoreClient.ListBuckets(account.AccountId, "")
	assert.Nil(t, err)
	assert.Less(t, 0, len(buckets))

	err = objectstoreClient.DeleteBucket(bucketName, account.AccountId, false)
	assert.Nil(t, err)

	err = objectstoreClient.DeleteTenant(account.AccountId)
	assert.Nil(t, err)

	err = manamgentclient.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

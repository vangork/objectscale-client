package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func TestTenant(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	objectstoreClient := CreateObjectstoreClient(t)
	defer objectstoreClient.Close()

	accountName := "testtenant"
	account := &objectscale.Account{
		Alias:             accountName,
		Description:       accountName,
		EncryptionEnabled: false,
	}
	account, err := manamgentclient.CreateAccount(account)
	assert.Nil(t, err)

	alias := "testtenant"
	blockSize := int64(5)
	tenant := &objectscale.Tenant{
		Alias:                  alias,
		Id:                     account.AccountId,
		IsEncryptionEnabled:    true,
		IsComplianceEnabled:    true,
		DefaultBucketBlockSize: blockSize,
	}
	_, err = objectstoreClient.CreateTenant(tenant)
	assert.Nil(t, err)

	tenant, err = objectstoreClient.GetTenant(account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, alias, tenant.Alias)
	assert.Equal(t, blockSize, tenant.DefaultBucketBlockSize)
	assert.Equal(t, account.AccountId, tenant.Id)
	assert.Equal(t, true, tenant.IsEncryptionEnabled)
	assert.Equal(t, true, tenant.IsComplianceEnabled)

	newAlias := "newtesttenant"
	newBlockSize := int64(10)
	tenant.Alias = newAlias
	tenant.DefaultBucketBlockSize = newBlockSize
	tenant, err = objectstoreClient.UpdateTenant(tenant)
	assert.Nil(t, err)
	assert.Equal(t, newAlias, tenant.Alias)
	assert.Equal(t, newBlockSize, tenant.DefaultBucketBlockSize)
	assert.Equal(t, account.AccountId, tenant.Id)
	assert.Equal(t, true, tenant.IsEncryptionEnabled)
	assert.Equal(t, true, tenant.IsComplianceEnabled)

	tenants, err := objectstoreClient.ListTenants("")
	assert.Nil(t, err)
	assert.NotEqual(t, 0, len(tenants))

	err = objectstoreClient.DeleteTenant(account.AccountId)
	assert.Nil(t, err)

	err = manamgentclient.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

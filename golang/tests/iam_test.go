package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func TestAccount(t *testing.T) {
	t.Parallel()

	client := CreateManagementClient(t)
	defer client.Close()

	name := "test"
	account := &objectscale.Account{
		Alias:             name,
		Description:       name,
		EncryptionEnabled: true,
		Tags:              []objectscale.Tag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}

	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	account, err = client.GetAccount(account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, name, account.Alias)
	assert.Equal(t, name, account.Description)
	assert.Equal(t, true, account.EncryptionEnabled)
	assert.Equal(t, 2, len(account.Tags))

	accounts, err := client.ListAccounts()
	assert.Nil(t, err)
	assert.NotEqual(t, 0, len(accounts))

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

func TestUser(t *testing.T) {
	t.Parallel()

	client := CreateManagementClient(t)
	defer client.Close()

	name := "test1"
	account := &objectscale.Account{
		Alias:             name,
		Description:       name,
		EncryptionEnabled: true,
		Tags:              []objectscale.Tag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}

	account, err := client.CreateAccount(account)
	assert.Nil(t, err)

	account, err = client.GetAccount(account.AccountId)
	assert.Nil(t, err)
	assert.Equal(t, name, account.Alias)
	assert.Equal(t, name, account.Description)
	assert.Equal(t, true, account.EncryptionEnabled)
	assert.Equal(t, 2, len(account.Tags))

	accounts, err := client.ListAccounts()
	assert.Nil(t, err)
	assert.NotEqual(t, 0, len(accounts))

	err = client.DeleteAccount(account.AccountId)
	assert.Nil(t, err)
}

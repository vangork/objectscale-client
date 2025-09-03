package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	//objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

const TEST_RG_ID string = "urn:storageos:ReplicationGroupInfo:b1733748-5695-4330-bb95-5f98df33cfdf:global"

func TestReplicationGroup(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	rg, err := manamgentclient.GetReplicationGroup(TEST_RG_ID)
	assert.Nil(t, err)

	newName := "replication_test_replication_group"
	newDescription := "replication test replication group description"
	enableRebalancing := !(rg.EnableRebalancing)
	isAllowAllNamespaces := !(rg.IsAllowAllNamespaces)

	rg.Name = newName
	rg.Description = newDescription
	rg.EnableRebalancing = enableRebalancing
	rg.IsAllowAllNamespaces = isAllowAllNamespaces
	state, err := manamgentclient.UpdateReplicationGroup(rg)
	assert.Nil(t, err)
	assert.Equal(t, true, state)

	rg, err = manamgentclient.GetReplicationGroup(TEST_RG_ID)
	assert.Nil(t, err)
	assert.Equal(t, newName, rg.Name)
	assert.Equal(t, newDescription, rg.Description)
	assert.Equal(t, enableRebalancing, rg.EnableRebalancing)
	assert.Equal(t, isAllowAllNamespaces, rg.IsAllowAllNamespaces)

	rgs, err := manamgentclient.ListReplicationGroups()
	assert.Nil(t, err)
	assert.Less(t, 0, len(rgs))
}

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func TestNamespace(t *testing.T) {
	manamgentclient := CreateManagementClient(t)
	defer manamgentclient.Close()

	namespaceName := "tenancy_test_namespace"

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

	namespace, err := manamgentclient.CreateNamespace(namespace)
	assert.Nil(t, err)
	assert.Equal(t, namespaceName, namespace.Name)
	assert.Equal(t, int64(-1), namespace.DefaultBucketBlockSize)
	assert.Equal(t, false, namespace.IsEncryptionEnabled)
	assert.Equal(t, REPLICATION_GROUP, namespace.DefaultDataServicesVpool)

	namespace.DefaultBucketBlockSize = 10
	namespace.BlockSize = 2
	namespace.NotificationSize = 2
	namespace.IsStaleAllowed = true
	namespace.UserMapping = []objectscale.UserMapping{
		{
			Attributes: []objectscale.Attribute{
				{
					Key: "aa",
					Value: []string{
						"aa",
					},
				},
			},
			Domain: "aa",
			Groups: []string{
				"aa",
			},
		},
	}
	namespace.RetentionClasses = objectscale.RetentionClasses{
		RetentionClass: []objectscale.RetentionClass{
			{
				Name:   "r1",
				Period: 1,
			},
		},
	}

	state, err := manamgentclient.UpdateNamespace(namespace)
	assert.Nil(t, err)
	assert.Equal(t, true, state)

	namespace, err = manamgentclient.GetNamespace(namespace.Id)
	assert.Nil(t, err)
	assert.Equal(t, namespaceName, namespace.Name)
	assert.Equal(t, int64(10), namespace.DefaultBucketBlockSize)
	assert.Equal(t, int64(2), namespace.BlockSize)
	assert.Equal(t, int64(2), namespace.NotificationSize)
	assert.Equal(t, true, namespace.IsStaleAllowed)
	assert.Equal(t, 1, len(namespace.UserMapping))
	assert.Equal(t, 1, len(namespace.RetentionClasses.RetentionClass))

	tenants, err := manamgentclient.ListNamespaces("")
	assert.Nil(t, err)
	assert.Less(t, 0, len(tenants))

	err = manamgentclient.DeleteNamespace(namespace.Id)
	assert.Nil(t, err)
}

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func CreateManagementClient(t *testing.T) *objectscale.ManagementClient {
	endpoint := "https://10.225.108.189:443"
	username := "root"
	password := "Password123@"
	insecure := true
	client, err := objectscale.NewManagementClient(endpoint, username, password, insecure)
	assert.Nil(t, err)
	return client
}

func CreateObjectstoreClient(t *testing.T) *objectscale.ObjectstoreClient {
	manamgentClient := CreateManagementClient(t)
	defer manamgentClient.Close()

	objectstore_endpoint := "https://10.225.108.187:4443"
	client, err := manamgentClient.NewObjectstoreClient(objectstore_endpoint)
	assert.Nil(t, err)
	return client
}

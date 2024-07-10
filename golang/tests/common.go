package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func CreateManagementClient(t *testing.T) *objectscale.ManagementClient {
	endpoint := "https://10.225.108.186:443"
	username := "root"
	password := "Password123@"
	insecure := true
	client, err := objectscale.NewManagementClient(endpoint, username, password, insecure)
	assert.Nil(t, err)
	return client
}

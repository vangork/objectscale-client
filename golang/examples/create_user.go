package main

import (
	"log"

	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func main() {
	endpoint := "https://10.225.108.189:443"
	username := "root"
	password := "Password123@"
	insecure := true

	client, err := objectscale.NewManagementClient(endpoint, username, password, insecure)
	if err != nil {
		log.Panicln("Fail to create objectscale client:", err.Error())
	}
	defer client.Close()

	accountId := "osai0a9250592a131336"
	userName := "test"
	arn := "urn:osc:iam:::policy/CRRFullAccess"

	user := &objectscale.User{
		UserName:  userName,
		Namespace: accountId,
		PermissionsBoundary: objectscale.PermissionsBoundary{
			PermissionsBoundaryArn: arn,
		},
		Tags: []objectscale.IamTag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}
	user, err = client.CreateUser(user)

	if err != nil {
		log.Println(err)
	} else {
		log.Printf("Got account: %v\n", user)
	}
}

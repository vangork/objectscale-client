//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

package main

import (
	"log"

	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func main() {
	endpoint := "https://10.225.108.217:4443"
	username := "root"
	password := "Password123!"
	insecure := true

	client, err := objectscale.NewManagementClient(endpoint, username, password, insecure)
	if err != nil {
		log.Panicln("Fail to create objectscale client:", err.Error())
	}
	defer client.Close()

	userName := "luis_user"
	namespace := "ns1"
	arn := "urn:ecs:iam:::policy/ECSS3FullAccess"

	user := &objectscale.User{
		UserName:  userName,
		Namespace: namespace,
		PermissionsBoundary: objectscale.PermissionsBoundary{
			PermissionsBoundaryArn:  arn,
			PermissionsBoundaryType: "",
		},
		Tags: []objectscale.IamTag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}
	user, err = client.CreateUser(user)

	if err != nil {
		log.Println(err)
	} else {
		log.Printf("Created user: %v\n", user)
	}
}

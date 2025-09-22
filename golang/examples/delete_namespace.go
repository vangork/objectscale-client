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

	id := "luis_namespace"
	err = client.DeleteNamespace(id)
	if err != nil {
		log.Println(err)
	} else {
		log.Printf("Deleted namespace: %s\n", id)
	}
}

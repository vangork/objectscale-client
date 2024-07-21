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

	alias := "test"
	account := &objectscale.Account{
		Alias: alias,
		Tags:  []objectscale.Tag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}
	account, err = client.CreateAccount(account)
	if err != nil {
		log.Panicln("Fail to create account:", err.Error())
	} else {
		log.Printf("Created account: %v\n", account)
	}
}

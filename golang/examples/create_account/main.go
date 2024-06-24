package main

import (
	"fmt"
	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func main() {
	endpoint := "https://10.225.108.186:443"
	username := "root"
	password := "Password123!"
	insecure := true

	client, err := objectscale.NewClient(endpoint, username, password, insecure)
	if err != nil {
		println("Fail to create objectscale client:", err.Error())
		return
	}
	defer client.Close()

	alias := "test"
	account := &objectscale.Account{
		Alias: alias,
		Tags:  []objectscale.Tag{{Key: "key1", Value: "value1"}, {Key: "key2", Value: "value2"}},
	}
	account, err = client.CreateAccount(account)
	if err != nil {
		println("Fail to create account:", err.Error())
		return
	} else {
		println("Created account:", account.AccountId)
		fmt.Printf("%v\n", account.Tags)
	}
}

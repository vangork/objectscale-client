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

	accounts, err := client.ListAccounts()
	if err != nil {
		println("Fail to list accounts:", err.Error())
		return
	} else {
		fmt.Printf("List accounts: %v\n", accounts)
	}
}

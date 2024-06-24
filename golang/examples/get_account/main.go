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

	id := "osai0a9250592a131336"
	account, err := client.GetAccount(id)
	if err != nil {
		println("Fail to get account:", err.Error())
		return
	} else {
		println("Got account:", account.Alias)
		fmt.Println("%v", account.Tags)
	}
}

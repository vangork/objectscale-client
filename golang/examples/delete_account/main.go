package main

import (
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

	id := "osai773e1b9936deb82a"
	err = client.DeleteAccount(id)
	if err != nil {
		println("Fail to delete account:", err.Error())
		return
	} else {
		println("Deleted account:", id)
	}
}

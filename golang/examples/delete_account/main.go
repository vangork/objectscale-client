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

	id := "osai697f6dd9f47ca078"
	err = client.DeleteAccount(id)
	if err != nil {
		log.Panicln("Fail to delete account:", err.Error())
	} else {
		log.Println("Deleted account:", id)
	}
}

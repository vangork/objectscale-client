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

	name := "luis_user"
	namespace := "ns1"
	err = client.DeleteUser(name, namespace)
	if err != nil {
		log.Println(err)
	} else {
		log.Printf("Deleted user: %s\n", name)
	}
}

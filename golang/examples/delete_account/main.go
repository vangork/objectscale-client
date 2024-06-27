package main

import (
	"log"

	objectscale "github.com/vangork/objectscale-client/golang/pkg"
)

func main() {
	endpoint := "https://10.225.108.186:443"
	username := "root"
	password := "Password123@"
	insecure := true

	client, err := objectscale.NewClient(endpoint, username, password, insecure)
	if err != nil {
		log.Panicln("Fail to create objectscale client:", err.Error())
	}
	defer client.Close()

	id := "osaide6244399dca21bc"
	err = client.DeleteAccount(id)
	if err != nil {
		log.Panicln("Fail to delete account:", err.Error())
	} else {
		log.Println("Deleted account:", id)
	}
}

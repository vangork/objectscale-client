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

	name := "luis_namespace"
	rp := "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global"

	namespace := &objectscale.Namespace{
		Name:                     name,
		DefaultDataServicesVpool: rp,
		DefaultBucketBlockSize:   -1,
		BlockSize:                2,
		NotificationSize:         2,
		NotificationSizeInCount:  -1,
		BlockSizeInCount:         -1,
		RetentionClasses: objectscale.RetionClasses{
			RetentionClass: []objectscale.RetionClass{
				{
					Name:   "r1",
					Period: 1,
				},
			},
		},
		UserMapping: []objectscale.UserMapping{
			{
				Attributes: []objectscale.Attribute{
					{
						Key: "aa",
						Value: []string{
							"aa",
						},
					},
				},
				Domain: "aa",
				Groups: []string{
					"aa",
				},
			},
		},
		AllowedVpoolsList:    []string{},
		DisallowedVpoolsList: []string{},
	}
	namespace, err = client.CreateNamespace(namespace)

	if err != nil {
		log.Println(err)
	} else {
		log.Printf("Created namespace: %v\n", namespace)
	}
}

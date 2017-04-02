//+build ignore

package main

import (
	"log"

	"github.com/minio/minio/pkg/ldap"
)

func main() {
	client := &ldap.Client{
		Base:         "dc=minio,dc=io",
		Host:         "172.21.0.2",
		Port:         "389",
		UseSSL:       false,
		BindDN:       "cn=minio,dc=minio,dc=io",
		BindPassword: "minio-readonly",
		UserFilter:   "(uid=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
	}

	if err := client.Dial(); err != nil {
		log.Fatal(err)
	}

	// It is the responsibility of the caller to close the connection
	defer client.Close()

	ok, err := client.UserExists("sgenomics")
	if err != nil {
		log.Fatal(err)
	}

	if !ok {
		log.Fatal("User not found sgenomics")
	}

	user, err := client.Login("sgenomics", "123456")
	if err != nil {
		log.Fatalf("Error authenticating user %s: %+v", "username", err)
	}
	log.Printf("User: %+v", user)

}

package main

import (
	"fmt"
	"log"
	"github.com/cs161-staff/project2-starter-code/tools"
)

func main(){
	username := "Alice"
	password := "password"
	tools.SignUp(username, password)

	ptr, err := tools.LoginCheck(username, "password")
	if err != nil{
		log.Fatal(err)
	}
	fmt.Printf("name: %s\npwd: %s\n", ptr.Username, ptr.Password)

	key, _ := ptr.GetKey("ENC-text.txt-0")
	fmt.Printf("%v\n", key[:5])

	key2, _ := ptr.GetKey("ENC-text.txt-0")
	fmt.Printf("%v\n", key2[:5])

}
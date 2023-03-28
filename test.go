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

	filename := "test.txt"
	content := []byte("hello world\n")

	ptr.StoreFile(filename, content)
	
	appendContent := []byte("another one\n")
	ptr.AppendtoFile(filename,appendContent )
	
	res, _ := ptr.LoadFile(filename)
	
	fmt.Printf("%v", string(res))
}
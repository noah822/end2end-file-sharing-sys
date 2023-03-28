package main

import (
	"fmt"
	"github.com/cs161-staff/project2-starter-code/tools"
)

func main(){
	username := "Alice"
	password := "password"
	tools.SignUp(username, password)

	ptr, _ := tools.LoginCheck(username, password)
	fmt.Printf("%v", ptr.Password)

}
package main

import (
	"fmt"
	// "log"
	"github.com/cs161-staff/project2-starter-code/tools"
)

func main(){

	/*
		Single user test checklist
		1. InitUser()
			return error:
				if duplicate name   -> pass
				if empty password   -> pass
		2. GetUser()
			return error:
				if not sign up -> pass
				if incorrect password -> pass
				if User struct is compromised -> pass
			
		3. StoreFile()
			if file exists, overwrite        -> pass
		
		4. LoadFile()
			return error:
				if not exist
	
	*/
	user := "Alice"
	pwd := "password"

	tools.InitUser(user, pwd)
	// if err != nil{
	// 	fmt.Printf("%v", err)
	// }

	ptr, err := tools.GetUser(user, pwd)
	if err != nil{
		fmt.Printf("%v", err)
	}

	// duplicate username test -> passed
	
	// ptr, err = tools.InitUser(user, pwd)		
	// if err != nil{
	// 	fmt.Printf("%v", err)
	// }
	// if err != nil{
	// 	fmt.Printf("%v", err)
	// }


	// StoreFile Overwrite test

	ptr.StoreFile("a.txt", []byte("hello\n"))
	content, err := ptr.LoadFile("b.txt")
	if err != nil{
		fmt.Printf("%v", err)
	}
	// content, _ := ptr.LoadFile("a.txt")

	// ptr.StoreFile("a.txt", []byte("world\n"))
	// content, _ = ptr.LoadFile("a.txt")
	fmt.Printf("%v", string(content))




	
}
package main

import (
	"fmt"
	// "log"
	"github.com/cs161-staff/project2-starter-code/tools"
)

func main(){
	user1 := "Alice"
	pwd1 := "password"
	tools.SignUp(user1, pwd1)
	ptr1, _ := tools.LoginCheck(user1, "password")
	// if err != nil{
	// 	log.Fatal(err)
	// }
	fmt.Printf("name: %s\npwd: %s\n", ptr1.Username, ptr1.Password)

	user2 := "Bob"
	pwd2 := "password"
	tools.SignUp(user2, pwd2)
	ptr2, _ := tools.LoginCheck(user2, "password")
	// if err != nil{
	// 	log.Fatal(err)
	// }
	fmt.Printf("name: %s\npwd: %s\n", ptr2.Username, ptr2.Password)

	A := "test.txt"
	content := []byte("hello world\n")

	ptr1.StoreFile(A, content)
	inviteptr, _ := ptr1.CreateInvitation(A, "Bob")
	ptr2.AcceptInvitation("Alice", inviteptr, "another.txt")

	ptr1.AppendtoFile(A, []byte("anotherone\n"))
	ptr2.AppendtoFile("another.txt", []byte("another\n"))

	content, _ = ptr2.LoadFile("another.txt")

	fmt.Printf("%v", string(content))


	
}
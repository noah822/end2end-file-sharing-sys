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

	user3 := "Coco"
	pwd3 := "password"
	tools.SignUp(user3, pwd3)
	ptr3, _ := tools.LoginCheck(user3, "password")

	A := "test.txt"
	content := []byte("hello world\n")

	ptr1.StoreFile(A, content)

	// A invite B
	inviteptr, _ := ptr1.CreateInvitation(A, "Bob")
	ptr2.AcceptInvitation("Alice", inviteptr, "b.txt")

	// A invite C
	inviteptr, _ = ptr1.CreateInvitation(A, "Coco")
	ptr3.AcceptInvitation("Alice", inviteptr, "c.txt")
	

	// A revoke B
	ptr1.RevokeAccess("test.txt", "Bob")
	// test C

	ptr3.AppendtoFile("c.txt", []byte("kobe\n"))

	content, _ = ptr3.LoadFile("c.txt")



	fmt.Printf("%v", string(content))


	
}
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
				allow empty password   -> pass
				if empty username   -> pass
		2. GetUser()
			return error:
				if not sign up -> pass
				if incorrect password -> pass
				if User struct is compromised -> pass

		============No invitation yet============
		3. StoreFile()
			if file exists, overwrite        -> pass
			if filename empty -> pass
			if empty content -> pass
			namespace switch （different users different actions） -> pass
			single user different actions -> pass

			todo:
			the write cannot occur due to malicious action
		
		4. LoadFile()
			namespace switch -> pass
			return error:
				if not exist
		5. AppendToFile()
			namespace swtch -> pass
			empty string appended -> pass
			file does not exist -> pass

		// User sessions check:
		single user have login in in different places -> pass
		update file content in different devices -> pass
		different users login in the same time -> pass

		===============Testing on invitation=================
		1 拿了不应该拿的invitation
		2 发没有权限的文件（不存在）
		3 参数错误，比如B发给D D记录发给他的人是A
		4 重复文件名
		5 被邀请的人load -> pass
		6 被邀请的人append -> pass
		7 被邀请的人 rewrite ->pass
		8 revoke B
	*/
	user := "A"
	pwd := "123123"
	userB := "B "
	pwdB := "456456"
	ptr, err := tools.InitUser(user, pwd)
	if err != nil{
		fmt.Printf("%v", err)
	}

	ptr, err = tools.GetUser(user, pwd)
	if err != nil{
		fmt.Printf("%v", err)
	}

	//login in A in athother device
	ptr_A, err_A := tools.GetUser(user, pwd)
	if err != nil{
		fmt.Printf("%v", err_A)
	}
	fmt.Printf("user A login in in another device!\n")

	//create another user 
	
	ptrB, errB := tools.InitUser(userB, pwdB)		
	if errB != nil{
		fmt.Printf("%v", errB)
	}
	if errB != nil{
		fmt.Printf("%v", errB)
	}
	// login in userB
	ptrB, errB = tools.GetUser(userB, pwdB)
	if errB != nil{
		fmt.Printf("%v", errB)
	}

	// StoreFile Overwrite test

	ptr.StoreFile("b.txt", []byte("Original B file content\n"))
	content, err := ptr.LoadFile("b.txt")
	if err != nil{
		fmt.Printf("%v", err)
	}
	// content, _ := ptr.LoadFile("a.txt")
	fmt.Printf("%v", string(content))
	fmt.Printf("done\n")

	
	// B store another file 

	ptrB.StoreFile("a.txt",[]byte("???\n"))
	content_fB, _ := ptrB.LoadFile("a.txt")
	fmt.Printf("%v", string(content_fB))
	fmt.Printf("done\n")

	//A stores another file c.txt
	ptr.StoreFile("c.txt", []byte("cccccccc\n"))
	content_fc, err_fC := ptr.LoadFile("c.txt")
	if err_fC != nil{
		fmt.Printf("%v", err_fC)
	}
	// content, _ := ptr.LoadFile("a.txt")
	fmt.Printf("%v", string(content_fc))
	fmt.Printf("done\n")
	// check before A overwrites again
	content, _ = ptr.LoadFile("b.txt")
	fmt.Printf("%v", string(content))
	fmt.Printf("Now A starts to overwrite \n")
	// Then A overwrites the b.txt in the second device
	ptr_A.StoreFile("b.txt", []byte("New B file content\n"))
	// check this file in the first device!
	content, _ = ptr.LoadFile("b.txt")
	fmt.Printf("================begin=====================\n")
	fmt.Printf("%v", string(content))
	fmt.Printf("=================end======================\n")

	//Now A append file in device1
	err_append_A := ptr.AppendToFile("b.txt",[]byte("Appeding behavior in device 1..\n"))
	if err_append_A != nil{
		fmt.Printf("%v", err_append_A)
	}
	//check in device 2
	fmt.Printf("Checking in device 2 for appending file b.txt..\n")
	fmt.Printf("================begin=====================\n")
	content, _ = ptr_A.LoadFile("b.txt")
	fmt.Printf("%v", string(content))
	fmt.Printf("=================end======================\n")
	fmt.Printf("\n")

	//Start to invite people
	//More users
	userC := "C"
	pwdC := "pwdforC"
	userD := "D"
	pwdD := "pwdforD"
	userE := "E"
	pwdE := "pwdforE"
	userF := "F"
	pwdF := "pwdforF"
	userG := "G"
	pwdG := "pwdforG"
	ptrC, _ := tools.InitUser(userC, pwdC)
	ptrD, _ := tools.InitUser(userD, pwdD)
	ptrE, _ := tools.InitUser(userE, pwdE)
	ptrF, _ := tools.InitUser(userF, pwdF)
	ptrG, _ := tools.InitUser(userG, pwdG)
	ptrC, _  = tools.GetUser(userC, pwdC)
	ptrD, _ = tools.GetUser(userD, pwdD)
	ptrE, _ = tools.GetUser(userE, pwdE)
	ptrF, _ = tools.GetUser(userF, pwdF)
	ptrG, _ = tools.GetUser(userG, pwdG)
	//  (b.txt)A
	//  	B           C
	//	D   E				G
	//F
	fmt.Printf("Now A invite B from device1\n")
	A_inivite_B, _ := ptr.CreateInvitation("b.txt",userB)

	fmt.Printf("Now B accept inivation from device1\n")
	b_local_name_f := "B_b.txt"
	ptrB.AcceptInvitation(user,A_inivite_B,b_local_name_f)

	fmt.Printf("Now B download file from device1\n")
	fmt.Printf("================begin=====================\n")
	content, _ = ptrB.LoadFile(b_local_name_f)
	fmt.Printf("%v", string(content))
	fmt.Printf("=================end======================\n")
	fmt.Printf("\n")

	fmt.Printf("Now A invite C from device2\n")
	A_inivite_C, _ := ptr_A.CreateInvitation("b.txt",userC)
	fmt.Printf("Now C accept inivation from device1\n")
	c_local_name_f := "C_b.txt"
	ptrC.AcceptInvitation(user,A_inivite_C,c_local_name_f)

	fmt.Printf("Now C append file from device1\n")
	err_append_C := ptrC.AppendToFile(c_local_name_f,[]byte("C is Appeding from device 1..\n"))
	if err_append_C != nil{
		fmt.Printf("%v", err_append_C)
	}

	
	// login B in device 2
	device2_B, _ := tools.GetUser(userB, pwdB)
	//check fileb in device 2:
	fmt.Printf("================begin=====================\n")
	content, _ = device2_B.LoadFile(b_local_name_f)
	fmt.Printf("%v", string(content))
	fmt.Printf("=================end======================\n")
	fmt.Printf("\n")
	//B invite D from device 2
	fmt.Printf("Now B invite D from device2\n")
	B_inivite_D, _ := ptrB.CreateInvitation(b_local_name_f,userD)
	fmt.Printf("Now D accept inivation from device1\n")
	d_local_name_f := "D_b.txt"
	ptrD.AcceptInvitation(userB,B_inivite_D,d_local_name_f)
	// fmt.Printf("Now D load file b.txt from device1\n")
	// fmt.Printf("================begin=====================\n")
	// content, _ = ptrD.LoadFile(d_local_name_f)
	// fmt.Printf("%v", string(content))
	// fmt.Printf("=================end======================\n")
	// fmt.Printf("\n")

	//continue..
	//B invites E
	B_inivite_E, _ := ptrB.CreateInvitation(b_local_name_f,userE)
	fmt.Printf("Now E accept inivation from device1\n")
	e_local_name_f := "E_b.txt"
	ptrE.AcceptInvitation(userB,B_inivite_E,e_local_name_f)

	// fmt.Printf("Now E load file b.txt from device1\n")
	// fmt.Printf("================begin=====================\n")
	// content, _ = ptrE.LoadFile(e_local_name_f)
	// fmt.Printf("%v", string(content))
	// fmt.Printf("=================end======================\n")
	// fmt.Printf("\n")

	//D invites F
	D_inivite_F, _ := ptrD.CreateInvitation(d_local_name_f,userF)
	fmt.Printf("Now F accept inivation from device1\n")
	f_local_name_f := "F_b.txt"
	ptrF.AcceptInvitation(userB,D_inivite_F,f_local_name_f)
	fmt.Printf("Now F store file b.txt from device1\n")
	// fmt.Printf("================begin=====================\n")
	ptrF.StoreFile(f_local_name_f,[]byte("F rewrites the file!\n"))
	// fmt.Printf("%v", string(content))
	// fmt.Printf("=================end======================\n")
	// fmt.Printf("\n")

	//C invites G
	C_inivite_G, _ := ptrC.CreateInvitation(c_local_name_f,userG)
	fmt.Printf("Now G accept inivation from device1\n")
	g_local_name_f := "G_b.txt"
	ptrG.AcceptInvitation(userC,C_inivite_G,g_local_name_f)
	fmt.Printf("Now G load file b.txt from device1\n")
	fmt.Printf("================begin=====================\n")
	content, _ = ptrG.LoadFile(g_local_name_f)
	fmt.Printf("%v", string(content))
	fmt.Printf("=================end======================\n")
	fmt.Printf("\n")

	//now A revokes inivation for B from device1
	ptr.RevokeAccess("b.txt",userB)
	ptrB.LoadFile(b_local_name_f)
	// ptrF.LoadFile(f_local_name_f)
}	
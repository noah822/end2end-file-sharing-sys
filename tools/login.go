package tools

import (
	// "fmt"
	"errors"
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
)

/*
	Implementation of user login utilities.

	The login routine is as follows:
	Say user A tries to login in with password $P, $PWD denotes correct password
		1. fetch h1 = H('A' || $PWD) pair from Datasotre using UUID($username/login)
		2. compare h1 with h2 = H('A' || $P)
			IF h1 == h2:
				SUCCESSFUL LOGIN
			ELSE:
				RAISE ERROR
*/

type LoginSlot struct {
	PasswordHash []byte
	Salt []byte
}

type User struct {
	Username string
	Password string
	Salt []byte
}

/*
	user slot structure in Datastore

	/login: Not Encrypted
	/SK: SymEnc Encrypted 
*/

func SignUp(username string, password string) (*User, error){

	salt := userlib.RandomBytes(32)
	passwordHash := userlib.Hash([]byte(username + password))

	PK, SK, _ := userlib.PKEKeyGen()
	userlib.KeystoreSet(username, PK)

	loginSlot := LoginSlot {
		PasswordHash: passwordHash,
		Salt: salt,
	}

	sharedKeyMenu := SharedKeyMenu {
		Menu: make(map[string] []byte),
	}

	ptr := &User {
		Username: username,
		Password: password,
		Salt: salt,
	}


	ptr.EncMacStoreDS("SK", SK)
	ptr.EncMacStoreDS("Menu", sharedKeyMenu)

	stream, _ := json.Marshal(loginSlot)
	StoreDS(username + "/login", stream)
	return ptr, nil
}


func LoginCheck(username string, password string) (*User, error) {
	var loginSlot LoginSlot
	stream, err := DecRetrieveDS(nil, username + "/login")
	if err != nil{
		return nil, err
	}
	err = json.Unmarshal(stream, &loginSlot)

	hash := userlib.Hash([]byte(username + password))
	if (ByteCompare(loginSlot.PasswordHash, hash)){
		userdataptr := &User {
			Username: username,
			Password: password,
			Salt: loginSlot.Salt,
		}
		return userdataptr, nil
	}

	err = errors.New("Incorrect username or password")
	return nil, err
}




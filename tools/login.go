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
	Signature []byte
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

	var err error
	salt := userlib.RandomBytes(32)
	passwordHash := userlib.Hash([]byte(username + password))

	PK, SK, _ := userlib.PKEKeyGen()
	SignKey, VerifyKey, _ := userlib.DSKeyGen();


	// sign the hash using generated SK
	signature, _ := userlib.DSSign(SignKey, passwordHash)

	err = userlib.KeystoreSet(username+"/DS", VerifyKey)
	err = userlib.KeystoreSet(username, PK)
	if err != nil {
		return nil, errors.New("Username already exists!")
	}

	loginSlot := LoginSlot {
		PasswordHash: passwordHash,
		Signature: signature,
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
	ptr.EncMacStoreDS("DSSK", SignKey)

	ptr.EncMacStoreDS("Menu", sharedKeyMenu)

	stream, _ := json.Marshal(loginSlot)
	StoreDS(username + "/login", stream)
	return ptr, nil
}


func LoginCheck(username string, password string) (*User, error) {
	var loginSlot LoginSlot
	verifyKey, ok := userlib.KeystoreGet(username + "/DS")
	if !ok {
		return nil, errors.New("User %s has not registered!")
	}


	stream, err := DecRetrieveDS(nil, username + "/login")
	if err != nil{
		return nil, errors.New("User %s has not registered!")
	}
	err = json.Unmarshal(stream, &loginSlot)

	// check signature
	err = userlib.DSVerify(
		verifyKey,
		loginSlot.PasswordHash,
		loginSlot.Signature,
	)
	if err != nil{
		return nil, errors.New("DataStore is likely to be tampered")
	}


	hash := userlib.Hash([]byte(username + password))
	if (ByteCompare(loginSlot.PasswordHash, hash)){
		userdataptr := &User {
			Username: username,
			Password: password,
			Salt: loginSlot.Salt,
		}
		return userdataptr, nil
	}

	err = errors.New("Incorrect password")
	return nil, err
}




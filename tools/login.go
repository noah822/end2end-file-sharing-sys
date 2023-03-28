package tools

import (
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

func SignUp(username string, password string) error{
	salt := userlib.RandomBytes(32)
	passwordHash := userlib.Hash([]byte(username + password))
	loginSlot := LoginSlot {
		PasswordHash: passwordHash,
		Salt: salt,
	}
	StoreDS(username + "/login", loginSlot)
	return nil
}


func LoginCheck(username string, password string) (*User, error) {
	var loginSlot LoginSlot
	RetrieveDS(username + "/login", &loginSlot)

	hash := userlib.Hash([]byte(username + password))
	if (ByteCompare(loginSlot.PasswordHash, hash)){
		userdataptr := &User {
			Username: username,
			Password: password,
			Salt: loginSlot.Salt,
		}
		return userdataptr, nil
	}

	return nil, nil
}




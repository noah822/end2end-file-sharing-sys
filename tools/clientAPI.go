package tools

import (
	// "fmt"
	"errors"
// 	"encoding/json"
// 	userlib "github.com/cs161-staff/project2-userlib"
)


func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(password) == 0{
		return nil, errors.New("Empty password is not allowed!")
	}
	ptr, err := SignUp(username, password)
	if err != nil{
		return nil, err
	}
	return ptr, nil
}


func GetUser(username string, password string) (userdataptr *User, err error) {
	ptr, err := LoginCheck(username, password)
	return ptr, err
}


func (userdataptr *User) StoreFile(filename string, content []byte) error{
	ptr := userdataptr
	handler, _, _, err := ptr.OpenFile(filename)
	if err == nil{
		handler.Store(0, content)
		handler.FBC = 1
		handler.Size = len(content)
		ptr.FileMetaUpdate(filename, handler)
	}else{
		handler := ptr.CreateFile(filename, len(content))
		handler.Store(0, content)
	}
	return nil
}


func (userdataptr *User) AppendToFile(filename string, content []byte)(error){
	ptr := userdataptr
	handler, _, _, err := ptr.OpenFile(filename)

	if err != nil{
		return err
	}

	handler.FBC++
	handler.Size += len(content)

	handler.Store(handler.FBC-1, content)

	ptr.FileMetaUpdate(filename, handler)

	return nil

	// handler = ptr.OpenFile(filename)
}

func (userdataptr *User) LoadFile(filename string) ([]byte, error){
	ptr := userdataptr
	handler, _, _, err := ptr.OpenFile(filename)
	if err != nil{
		return nil, err
	}
	return handler.Load()
}
package tools

// import (
// 	"fmt"
// 	"errors"
// 	"encoding/json"
// 	userlib "github.com/cs161-staff/project2-userlib"
// )


func (userdataptr *User) StoreFile(filename string, content []byte) error{
	ptr := userdataptr
	handler := ptr.CreateFile(filename, len(content))
	return handler.Store(0, content)
}


func (userdataptr *User) AppendtoFile(filename string, content []byte){
	ptr := userdataptr
	handler, _, _ := ptr.OpenFile(filename)


	handler.FBC++
	handler.Size += len(content)

	handler.Store(handler.FBC-1, content)

	ptr.FileMetaUpdate(filename, handler)

	// handler = ptr.OpenFile(filename)
}




func (userdataptr *User) LoadFile(filename string) ([]byte, error){
	ptr := userdataptr
	handler, _, _ := ptr.OpenFile(filename)
	return handler.Load()
}
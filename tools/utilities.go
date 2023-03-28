package tools
import (
	"fmt"
	"errors"
	"encoding/json"
	"github.com/google/uuid"
	userlib "github.com/cs161-staff/project2-userlib"
)

func ByteCompare(b1, b2 []byte) bool {
	if len(b1) != len(b2){
		return false
	}
	for i:= range b1{
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

func RetrieveDS(index string, contentPtr interface{}) error {
	_uuid := GetUUID(index)
	fmt.Printf("%v\n", _uuid)
	stream, ok := userlib.DatastoreGet(_uuid)
	if !ok {
		panic("Error occurs in DataStore retrival")
	}
	newerr := json.Unmarshal(stream, contentPtr)
	return newerr
}

func StoreDS(index string, content interface{}) error {
	_uuid := GetUUID(index)
	fmt.Printf("%v\n", _uuid)
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(_uuid, contentBytes)
	return nil
}

func GetUUID(s string) uuid.UUID {
	hash := userlib.Hash([]byte(s))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		panic(errors.New("Error occurs when generating UUID from given string!"))
	}
	return deterministicUUID
}




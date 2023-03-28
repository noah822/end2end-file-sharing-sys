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


func RawRetrieveDS(index string) ([]byte, error){
	_uuid := GetUUID(index)
	fmt.Printf("%v\n", _uuid)
	stream, ok := userlib.DatastoreGet(_uuid)
	if !ok {
		err := errors.New("Error occurs when Datastore Retrieval")
		return nil, err
	}
	return stream, nil
	
}

func DecRetrieveDS(decKey interface{}, index string) ([]byte, error){
	_uuid := GetUUID(index)
	stream, ok := userlib.DatastoreGet(_uuid)
	if !ok {
		return nil, errors.New("Error occurs when Datastore Retrieval")
	}

	if decKey == nil{
		return stream, nil
	}
	
	switch decKey.(type) {
	case userlib.PKEDecKey:
		_decKey, ok := decKey.(userlib.PKEDecKey)
		if !ok {
			return nil, errors.New("Error occurs when key type casting")
		}
		ptext, err := userlib.PKEDec(_decKey, stream)
		return ptext, err
	default:
		ptext := userlib.SymDec(decKey.([]byte), stream)
		return ptext, nil
	}
}

func StoreDS(index string, content []byte){
	_uuid := GetUUID(index)
	userlib.DatastoreSet(_uuid, content)
}

func GetUUID(s string) uuid.UUID {
	hash := userlib.Hash([]byte(s))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		panic(errors.New("Error occurs when generating UUID from given string!"))
	}
	return deterministicUUID
}

/*
	Serialized-then-Enc
	SymEnc cannot take any other type other than []byte as input
	To other type, we first serialize it using json.Marshal()
				   then invoke SymEnc() API
*/

func SerThenEnc(encKey interface{}, content interface{})[]byte{
	stream, _ := json.Marshal(content)
	if encKey == nil {
		return stream
	}

	switch encKey.(type){
		case userlib.PKEEncKey:
			ctext, _ := userlib.PKEEnc(
				encKey.(userlib.PKEEncKey), stream)
			return ctext
		default:
			ctext := userlib.SymEnc(
				encKey.([]byte),
				userlib.RandomBytes(16),
				stream)
			return ctext
	}
}

/*
	Decrypt-then-Deserialize
*/






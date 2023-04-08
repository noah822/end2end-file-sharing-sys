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


func RetrieveDS(index string) ([]byte, error){
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

/*
	index is under the namespace the user specified
*/

func GuardedRetrieveDS(decKey []byte, macKey []byte, index string) ([]byte, error){
	_uuid := GetUUID(index)
	stream, ok := userlib.DatastoreGet(_uuid)
	if !ok {
		return nil, errors.New("Error occurs when Datastore Retrieval")
	}
	
	_macUUID := GetUUID(index + "/MAC")
	hmac, _ := userlib.DatastoreGet(_macUUID)

	if !MacCheck(macKey, stream, hmac){
		return nil, errors.New(
			fmt.Sprintf("%s has been tempared with!", index),
		)
	}
	ptext := userlib.SymDec(decKey, stream)
	return ptext, nil
}

func GuardedRetrieveDSUUID(decKey []byte, macKey []byte, encUUID uuid.UUID, macUUID uuid.UUID) ([]byte, error){
	stream, ok := userlib.DatastoreGet(encUUID)
	if !ok {
		return nil, errors.New("Error occurs when Datastore Retrieval")
	}
	
	hmac, _ := userlib.DatastoreGet(macUUID)

	if !MacCheck(macKey, stream, hmac){
		return nil, errors.New(
			fmt.Sprintf("file has been tampered with"),
		)
	}
	ptext := userlib.SymDec(decKey, stream)
	return ptext, nil
}



func MacCheck(key []byte, ctext []byte, hmac []byte)bool {
	_hmac, _ := userlib.HMACEval(key, ctext)
	ok := userlib.HMACEqual(hmac, _hmac)
	return ok
}

func StoreDS(index string, content []byte){
	_uuid := GetUUID(index)
	userlib.DatastoreSet(_uuid, content)
}

func GuardedStoreDS(encKey []byte, macKey []byte, index string, content interface {}){

	stream  := SerThenEnc(encKey, content)
	hmac, _ := userlib.HMACEval(macKey, stream)

	StoreDS(index, stream)
	StoreDS(index+"/MAC", hmac)
}

func GuardedStoreDSUUID(encKey []byte, macKey []byte, encUUID uuid.UUID, macUUID uuid.UUID, content interface {}){

	stream  := SerThenEnc(encKey, content)
	hmac, _ := userlib.HMACEval(macKey, stream)

	userlib.DatastoreSet(encUUID, stream)
	userlib.DatastoreSet(macUUID, hmac)
}



func (userdataptr *User) EncMacStoreDS(itemname string, item interface{}){
	ptr := userdataptr
	encKey, _ := ptr.GetKey("ENC-" + itemname)
	macKey, _ := ptr.GetKey("MAC-"+itemname)

	stream  := SerThenEnc(encKey, item)
	hmac, _ := userlib.HMACEval(macKey, stream)

	StoreDS(
		fmt.Sprintf("%s/%s", ptr.Username, itemname),
		stream,
	)

	StoreDS(
		fmt.Sprintf("%s/%s/MAC", ptr.Username, itemname),
		hmac,
	)
}

// func (handler *File) EncMacStoreDS(itemname string, item interface{}){
// 	encKey, _ := handler.GetKey("ENC-" + itemname)
// 	macKey, _ := handler.GetKey("MAC-"+itemname)

// 	stream  := SerThenEnc(encKey, item)
// 	hmac, _ := userlib.HMACEval(macKey, stream)

// 	StoreDS(
// 		fmt.Sprintf("%s/%s", ptr.Username, itemname),
// 		stream,
// 	)

// 	StoreDS(
// 		fmt.Sprintf("%s/%s/MAC", ptr.Username, itemname),
// 		hmac,
// 	)
// }



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
	Hybrid Encryption Scheme
*/

type Packet struct {
	SymKey []byte
	Content []byte
}


func HybridEnc(PK userlib.PKEEncKey, content []byte)[]byte{
	symKey := userlib.RandomBytes(16)
	encryptedSymKey, _ := userlib.PKEEnc(PK, symKey)
	ctext := userlib.SymEnc(symKey, userlib.RandomBytes(16), content)

	stream, _ := json.Marshal(Packet{encryptedSymKey, ctext})
	return stream
}

/*
	Only return decrypted content
*/

func HybridDec(SK userlib.PKEDecKey, stream []byte)[]byte{
	var packet Packet
	json.Unmarshal(stream, &packet)
	symKey, _ := userlib.PKEDec(SK, packet.SymKey)
	ptext := userlib.SymDec(symKey, packet.Content)
	return ptext
} 





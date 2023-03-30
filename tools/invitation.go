package tools

import (
	"fmt"
// 	"errors"
	// "log" 

	"github.com/google/uuid"
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
)



type Invitation struct{
	Owner string
	Recepient string
	Filename string
	MetaEncKey []byte
	MetaMacKey []byte
}
/*
	Procedure of creating invitation:
		1. fetch metaEncKey and metaMacKey from $Username/Menu
		2. initialize Invitatin object
			feature can be added here:
				first sign using owner's private key
		3. store it in Datastore en
			Invation naming convention
			Inv/<OwerName>-<RecepientName>-<Filename>
			Inv/<OwerName>-<RecepientName>-<Filename>/Sign
*/

func (userdataptr *User) CreateInvitation (filename string, recipientUsername string)(uuid.UUID, error){
	ptr := userdataptr
	handler := ptr.OpenFile(filename)

	var _ownername string
	var _filename string
	if handler.Linked {
		_ownername = handler.Link.Owner
		_filename = handler.Link.Filename
	}else{
		_ownername = ptr.Username
		_filename = filename
	}

	metaEncKey, metaMacKey, _ := ptr.__getMenuKey(filename)
	inv := Invitation{
		Owner: _ownername,
		Recepient: recipientUsername,
		Filename: _filename,
		MetaEncKey: metaEncKey,
		MetaMacKey: metaMacKey,
	}

	recipientPK, ok := userlib.KeystoreGet(recipientUsername)
	if !ok {
		panic("Recepient does not exist")
	}

	index := fmt.Sprintf("Inv/%s-%s-%s", ptr.Username, recipientUsername, filename)

	stream, _ := json.Marshal(inv)

	ctext := HybridEnc(recipientPK, stream)
	/*
		ctext, err := userlib.PKEEnc(recipientPK, stream)
		PKEEnc does not support long plaintext

		use hybrid encryption instead
	*/


	// if err != nil{
	// 	log.Fatal(err)
	// }


	StoreDS(index, ctext)
	return GetUUID(index), nil
}



func (userdataptr *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (error){
	ptr := userdataptr
	encSKKey, _ := ptr.GetKey("ENC-SK")
	macSKKey, _ := ptr.GetKey("MAC-SK")

	var SK userlib.PKEDecKey
	stream, _ := GuardedRetrieveDS(
		encSKKey, macSKKey,
		ptr.Username + "/SK",
	)
	json.Unmarshal(stream, &SK)

	var inv Invitation
	ctext, _ := userlib.DatastoreGet(invitationPtr)
	ptext := HybridDec(SK, ctext)
	json.Unmarshal(ptext, &inv)


	// using invitation index to create soft-linked file
	handler := File{
		Linked: true,
		Link : SoftLink{inv.Owner, inv.Filename},
	}

	ptr.__setMenuKey(filename, inv.MetaEncKey, inv.MetaMacKey)
	GuardedStoreDS(
		inv.MetaEncKey, inv.MetaMacKey,
		fmt.Sprintf("%s/%s/Meta", ptr.Username, filename),
		handler,
	)

	return nil
}








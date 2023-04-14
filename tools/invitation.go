package tools

import (
	"fmt"
	"errors"
	// "log" 

	"github.com/google/uuid"
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
)



type Invitation struct{
	// Sharer string
	// Filename string
	MetaBlockUUID uuid.UUID
	MetaMacUUID uuid.UUID
	Recepient string
	MetaEncKey []byte
	MetaMacKey []byte
}

type RecipientTuple struct {
	MetaBlockUUID uuid.UUID
	MetaMacUUID uuid.UUID
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
	_, _, _, err := ptr.OpenFile(filename)
	if err != nil{
		return uuid.UUID{}, errors.New("File sharer does not have access to the file or the file does not exist!")
	}

	metaEncKey, metaMacKey, _ := ptr.__getMenuKey(filename)

	// metaEncKey, metaMacKey, _ := ptr.__getMenuKey(filename)
	inv := Invitation{
		MetaBlockUUID: GetUUID(
			fmt.Sprintf("%s/%s/Meta", ptr.Username, filename),
		),
		MetaMacUUID: GetUUID(
			fmt.Sprintf("%s/%s/Meta/MAC", ptr.Username, filename),
		),
		Recepient: recipientUsername,
		MetaEncKey: metaEncKey,
		MetaMacKey: metaMacKey,
	}

	recipientPK, ok := userlib.KeystoreGet(recipientUsername)
	if !ok {
		panic("Recepient does not exist")
	}

	index := fmt.Sprintf("Inv/%s-%s-%s", ptr.Username, recipientUsername, filename)

	invStream, _ := json.Marshal(inv)

	dsskEncKey, _ := ptr.GetKey("ENC-DSSK")
	dsskMacKey, _ := ptr.GetKey("MAC-DSSK")

	stream, err := GuardedRetrieveDS(
		dsskEncKey, dsskMacKey,
		fmt.Sprintf("%s/DSSK", ptr.Username),
	)
	if err != nil{
		return uuid.UUID{}, err
	}

	var signKey userlib.DSSignKey
	json.Unmarshal(stream, &signKey)

	ctext, err := HybridEnc(recipientPK, signKey, invStream)
	if err != nil{
		return uuid.UUID{}, err
	}
	

	/*
		ctext, err := userlib.PKEEnc(recipientPK, stream)
		PKEEnc does not support long plaintext

		use hybrid encryption instead
	*/


	StoreDS(index, ctext)
	return GetUUID(index), nil
}



func (userdataptr *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (error){
	ptr := userdataptr
	// check whether the file name already exists under the recipient's namespace
	_, _, _, err := ptr.OpenFile(filename)
	if err == nil{
		return errors.New("Filename already exists in recipient's namespace!")
	}


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

	verifyKey, ok := userlib.KeystoreGet(senderUsername + "/DS")

	if !ok{
		return errors.New("Invalid Sender Name!")
	}

	ptext, err := HybridDec(SK, userlib.DSVerifyKey(verifyKey), ctext)
	if err != nil{
		return errors.New("Invalid Sender Name!")
	}

	if err != nil{
		return err
	}
	json.Unmarshal(ptext, &inv)


	// using invitation index to create soft-linked file
	handler := File{
		Linked: true,
		Link : SoftLink{inv.MetaBlockUUID, inv.MetaMacUUID, inv.MetaEncKey, inv.MetaMacKey},
		AccessList: make(map[string]RecipientTuple),
	}


	metaEncKey, metaMacKey, _ := ptr.__initMenuKey(filename)


	GuardedStoreDS(
		metaEncKey, metaMacKey,
		fmt.Sprintf("%s/%s/Meta", ptr.Username, filename),
		handler,
	)

	// update the AccessList in sharer's meta block
	// AccessList[$recepient] = ("filename", metaEncKey, metaMacKey)

	recipientTuple := RecipientTuple{
		MetaBlockUUID: GetUUID(
			fmt.Sprintf("%s/%s/Meta", ptr.Username, filename),
		),
		MetaMacUUID: GetUUID(
			fmt.Sprintf("%s/%s/Meta/MAC", ptr.Username, filename),
		), 
		MetaEncKey: metaEncKey,
		MetaMacKey: metaMacKey,
	}

	stream, _ = GuardedRetrieveDSUUID(
		inv.MetaEncKey, inv.MetaMacKey,
		inv.MetaBlockUUID, inv.MetaMacUUID,
	)
	
	json.Unmarshal(stream, &handler)
	handler.AccessList[ptr.Username] = recipientTuple

	GuardedStoreDSUUID(
		inv.MetaEncKey, inv.MetaMacKey,
		inv.MetaBlockUUID, inv.MetaMacUUID,
		handler,
	)

	return nil
}


func (userdataptr *User) RevokeAccess(filename string, recipientUsername string)(err error){
	ptr := userdataptr
	handler, _, _, _ := ptr.OpenFile(filename)
	newMetaEncKey, newMetaMacKey, _ := ptr.__initMenuKey(filename)

	/*
		1. Re-encrypt meta block and file content
		2. distribute to direct children
	*/
	var prevHandler File = File{
		Filename: handler.Filename,
		Username: handler.Username,
		GKey: handler.GKey,
	}

	newGKey := userlib.RandomBytes(16)
	handler.GKey = newGKey


	// Re-encrypt/mac file content
	for i:=0; i<handler.FBC; i++{
		blockContent, err := prevHandler.LoadBlock(i)
		if err != nil{
			return errors.New("File has been compromised!")
		}
		handler.Store(i, blockContent)
	}

	delete(handler.AccessList, recipientUsername)

	// distribute new metaKeys
	for name, recipientTuple := range handler.AccessList{
		fmt.Println(name)
		var recipientMeta File
		stream, _ := GuardedRetrieveDSUUID(
			recipientTuple.MetaEncKey,
			recipientTuple.MetaMacKey,
			recipientTuple.MetaBlockUUID,
			recipientTuple.MetaMacUUID,
		)
		json.Unmarshal(stream, &recipientMeta)

		recipientMeta.Link.MetaEncKey = newMetaEncKey
		recipientMeta.Link.MetaMacKey = newMetaMacKey

		GuardedStoreDSUUID(
			recipientTuple.MetaEncKey,
			recipientTuple.MetaMacKey,
			recipientTuple.MetaBlockUUID,
			recipientTuple.MetaMacUUID,
			recipientMeta,
		)
	}

	GuardedStoreDS(
		newMetaEncKey, newMetaMacKey,
		fmt.Sprintf("%s/%s/Meta", ptr.Username, filename),
		handler,
	)
	
	return nil
}








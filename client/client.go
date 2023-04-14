package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
// type User struct {
// 	Username string
// 	Password string
// 	Salt []byte
// 	// You can add other attributes here if you want! But note that in order for attributes to
// 	// be included when this struct is serialized to/from JSON, they must be capitalized.
// 	// On the flipside, if you have an attribute that you want to be able to access from
// 	// this struct's methods, but you DON'T want that value to be included in the serialized value
// 	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// 	// begins with a lowercase letter).
// }

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0{
		return nil, errors.New("Empty username is not allowed!")
	}
	ptr, err := SignUp(username, password)
	if err != nil{
		return nil, err
	}
	return ptr, nil
}


func GetUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0{
		return nil, errors.New(strings.ToTitle("Empty username is not allowed!"))
	}
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
// func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
// 	invitationPtr uuid.UUID, err error) {
// 	return
// }

// func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
// 	return nil
// }

// func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
// 	return nil
// }

/*
	STRUCT DEF

*/
type SharedKeyMenu struct {
	Menu map[string] []byte
}

type SoftLink struct {
	// Owner string
	// Filename string
	MetaBlockUUID uuid.UUID
	MetaMacUUID uuid.UUID
	MetaEncKey []byte
	MetaMacKey []byte
} 

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


type File struct {
	// Soft link to another file if necessary, default: nil 
	Linked bool
	Link SoftLink
	Prefix []byte

	Username string
	Filename string
	Size int
	GKey []byte

	// file access privillege control
	AccessList map[string]RecipientTuple

	// file block count used for efficient file append
	FBC int
}


type LoginSlot struct {
	EncPasswordHash []byte
	Signature []byte
	Salt []byte
}

type User struct {
	Username string
	Password string
	Salt []byte
}

/*
	KEY MANAGEMENT
*/

func (userdataptr *User) GetKey(purpose string) ([]byte, error){
	ptr := userdataptr
	core_key := userlib.Argon2Key(
		[]byte(ptr.Password),
		ptr.Salt,
		16,
	)
	key, err := userlib.HashKDF(core_key, []byte(purpose))
	return key[:16], err
}

func (fileptr *File) GetKey(purpose string)([]byte, error){
	ptr := fileptr
	GKey := ptr.GKey
	key, err := userlib.HashKDF(GKey, []byte(purpose))
	return key[:16], err
}

/*
	UTILITIES
*/
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
	Signature []byte
	SymKey []byte
	Content []byte
}


func HybridEnc(PK userlib.PKEEncKey, signKey userlib.DSSignKey, content []byte)([]byte, error){
	symKey := userlib.RandomBytes(16)
	encryptedSymKey, _ := userlib.PKEEnc(PK, symKey)
	ctext := userlib.SymEnc(symKey, userlib.RandomBytes(16), content)

	var container []byte = append(encryptedSymKey, ctext...)


	signature, err := userlib.DSSign(signKey, container)
	if err != nil{
		return nil, errors.New("Error occurs when signing the invitation!")
	}

	stream, _ := json.Marshal(Packet{signature, encryptedSymKey, ctext})
	return stream, nil
}

/*
	Only return decrypted content
*/

func HybridDec(SK userlib.PKEDecKey, verifyKey userlib.DSVerifyKey , stream []byte)([]byte, error){
	var packet Packet
	json.Unmarshal(stream, &packet)

	var container []byte = append(packet.SymKey, packet.Content...)
	err := userlib.DSVerify(verifyKey, container, packet.Signature)

	if err != nil{
		return nil, errors.New("Invitation has been tampered with!")
	}

	symKey, _ := userlib.PKEDec(SK, packet.SymKey)
	ptext := userlib.SymDec(symKey, packet.Content)
	return ptext, nil
} 


/*
	LOGIN
*/

func SignUp(username string, password string) (*User, error){

	var err error
	salt := userlib.RandomBytes(32)
	passwordHash := userlib.Hash([]byte(username + password))

	PK, SK, _ := userlib.PKEKeyGen()
	SignKey, VerifyKey, _ := userlib.DSKeyGen();


	// sign the hash using generated SK
	
	err = userlib.KeystoreSet(username+"/DS", VerifyKey)
	err = userlib.KeystoreSet(username, PK)
	if err != nil {
		return nil, errors.New("Username already exists!")
	}
	
	encKey := userlib.Argon2Key([]byte(password), salt, 16)
	
	encPasswordHash := userlib.SymEnc(
		encKey, userlib.RandomBytes(16), 
		passwordHash,
	)
	signature, _ := userlib.DSSign(SignKey, encPasswordHash)

	loginSlot := LoginSlot {
		EncPasswordHash: encPasswordHash,
		Signature: signature,
		Salt: salt,
	}

	sharedKeyMenu := SharedKeyMenu {
		Menu: make(map[string] []byte),
	}
	prefixMenu := make(map[string] []byte)

	ptr := &User {
		Username: username,
		Password: password,
		Salt: salt,
	}


	ptr.EncMacStoreDS("SK", SK)
	ptr.EncMacStoreDS("DSSK", SignKey)

	ptr.EncMacStoreDS("Menu", sharedKeyMenu)
	ptr.EncMacStoreDS("Prefix", prefixMenu)

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
		loginSlot.EncPasswordHash,
		loginSlot.Signature,
	)
	if err != nil{
		return nil, errors.New("DataStore is likely to be tampered")
	}

	decKey := userlib.Argon2Key([]byte(password), loginSlot.Salt, 16)

	passwordHash := userlib.SymDec(decKey, loginSlot.EncPasswordHash)


	hash := userlib.Hash([]byte(username + password))
	if (ByteCompare(passwordHash, hash)){
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

/*
	FILE MANAGEMENT
*/

func (userdataptr *User)CreateFile(filename string, size int) *File {
	ptr := userdataptr
	metaEncKey, metaMacKey, _ := ptr.__initMenuKey(filename)

	prefix, _ := ptr.__initPrefix(filename)


	handler := File{
		Linked: false,
		Username: ptr.Username,
		Filename: filename,
		Prefix: prefix,

		GKey: userlib.RandomBytes(16),
		AccessList: make(map[string]RecipientTuple),
		Size: size,
		FBC: 1,
	} 

	/*
		Assign file control block
		encryption and mac key
	*/
	
	GuardedStoreDS(
		metaEncKey, metaMacKey,
		fmt.Sprintf("%v/%s/%s/Meta", prefix, ptr.Username, filename),
		handler,
	)
	
	return &handler
}


func (userdataptr* User) __initMenuKey(filename string) ([]byte, []byte, error){
	ptr := userdataptr
	menuEncKey, _ := ptr.GetKey("ENC-Menu")
	menuMacKey, _ := ptr.GetKey("MAC-Menu")

	stream, err := GuardedRetrieveDS(
		menuEncKey, menuMacKey,
		ptr.Username + "/Menu",
	)
	if err != nil{
		panic("Menu has been tampered with!")
	}

	var _menu SharedKeyMenu
	json.Unmarshal(stream, &_menu)



	metaEncKey := userlib.RandomBytes(16)
	metaMacKey := userlib.RandomBytes(16)

	_menu.Menu[filename] = metaEncKey
	_menu.Menu[filename + "/MAC"] = metaMacKey

	ptr.EncMacStoreDS("Menu", _menu)

	return metaEncKey, metaMacKey, nil
}

func (userdataptr* User) __initPrefix(filename string)([]byte, error){
	ptr := userdataptr

	var prefixMenu map[string] []byte
	prefix := userlib.RandomBytes(16)

	prefixEncKey, _ := ptr.GetKey("ENC-Prefix")
	prefixMacKey, _ := ptr.GetKey("MAC-Prefix")

	stream, _ := GuardedRetrieveDS(
		prefixEncKey, prefixMacKey, 
		ptr.Username + "/Prefix",
	)

	json.Unmarshal(stream, &prefixMenu)
	prefixMenu[filename] = prefix

	ptr.EncMacStoreDS("Prefix", prefixMenu)
	return prefix, nil

}

func (userdataptr* User) __getPrefix(filename string)([]byte, error){
	ptr := userdataptr
	
	var prefixMenu map[string] []byte
	
	prefixEncKey, _ := ptr.GetKey("ENC-Prefix")
	prefixMacKey, _ := ptr.GetKey("MAC-Prefix")
	
	stream, _ := GuardedRetrieveDS(
		prefixEncKey, prefixMacKey, 
		ptr.Username + "/Prefix",
	)
	
	json.Unmarshal(stream, &prefixMenu)

	
	return prefixMenu[filename], nil

}

func (userdataptr *User) __getMenuKey(filename string) ([]byte, []byte, error){
	ptr := userdataptr
	menuEncKey, _ := ptr.GetKey("ENC-Menu")
	menuMacKey, _ := ptr.GetKey("MAC-Menu")

	stream, _ := GuardedRetrieveDS(
		menuEncKey, menuMacKey,
		ptr.Username + "/Menu",
	)
	var _menu SharedKeyMenu
	json.Unmarshal(stream, &_menu)

	metaEncKey, ok := _menu.Menu[filename]
	if !ok {
		return nil, nil, errors.New("File does not exist!")
	}
	metaMacKey := _menu.Menu[filename + "/MAC"]

	return metaEncKey, metaMacKey, nil
}

func (userdataptr *User) __setMenuKey(filename string, encKey []byte, macKey []byte) (error){
	ptr := userdataptr
	menuEncKey, _ := ptr.GetKey("ENC-Menu")
	menuMacKey, _ := ptr.GetKey("MAC-Menu")

	stream, err := GuardedRetrieveDS(
		menuEncKey, menuMacKey,
		ptr.Username + "/Menu",
	)

	if err != nil{
		panic("Menu has been tampered with!")
	}
	
	var _menu SharedKeyMenu
	json.Unmarshal(stream, &_menu)

	_menu.Menu[filename] = encKey
	_menu.Menu[filename + "/MAC"] = macKey


	ptr.EncMacStoreDS("Menu", _menu)

	return nil
}

/*
	Handle the case where File is actually a soft-linked version file

*/

func (userdataptr* User) OpenFile(filename string) (*File, []byte, []byte, error){
	ptr := userdataptr

	
	metaEncKey, metaMacKey, err := ptr.__getMenuKey(filename)
	if err != nil{
		return nil, nil, nil, errors.New("File does not exist!")
	}
	
	prefix, _ := ptr.__getPrefix(filename)

	index := fmt.Sprintf("%v/%s/%s/Meta", prefix, ptr.Username, filename)
	
	var handler File
	stream, err := GuardedRetrieveDS(metaEncKey, metaMacKey, index)

	if err != nil{
		return nil, nil, nil, errors.New("File has been compromised!")
	}
	json.Unmarshal(stream, &handler)

	if !handler.Linked{
		return &handler, metaEncKey, metaMacKey, nil
	}else{
		handler, metaEncKey, metaMacKey, err := __shareTreeTraverse(&handler)
		if err != nil{
			return nil, nil, nil, err
		}
		return handler, metaEncKey, metaMacKey, nil
	}

}

func __shareTreeTraverse(handler *File) (*File, []byte, []byte, error){
	cur := handler
	var metaEncKey []byte
 	var metaMacKey []byte
	for cur.Linked {
		metaEncKey = cur.Link.MetaEncKey
		metaMacKey = cur.Link.MetaMacKey
		stream, err := GuardedRetrieveDSUUID(
			cur.Link.MetaEncKey, cur.Link.MetaMacKey,
			cur.Link.MetaBlockUUID, cur.Link.MetaMacUUID,
		)
		if err != nil{
			return nil, nil, nil, errors.New("Access is likely to be revoked!")
		}
		json.Unmarshal(stream, &cur)
	}
	return cur, metaEncKey, metaMacKey, nil
}

func (handler *File) Store(blockNum int, content []byte) error {
	fileEncKey, _ := handler.GetKey(
		fmt.Sprintf("ENC-%v", blockNum),
	) 
	fileMacKey, _ := handler.GetKey(
		fmt.Sprintf("MAC-%v", blockNum),
	)

	// Enc-then-Mac
	ctext   := userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), content)
	hmac, _ := userlib.HMACEval(fileMacKey, ctext)
	StoreDS(
		fmt.Sprintf("%v/%s/%s/%v", handler.Prefix, handler.Username, handler.Filename, blockNum),
		ctext)

	StoreDS(
		fmt.Sprintf("%v/%s/%s/%v/MAC", handler.Prefix, handler.Username, handler.Filename, blockNum),
		hmac)
	
	return nil
}


func (handler *File) LoadBlock(blockNum int) ([]byte, error){
	fileEncKey, _ := handler.GetKey(
		fmt.Sprintf("ENC-%v", blockNum),
	) 
	fileMacKey, _ := handler.GetKey(
		fmt.Sprintf("MAC-%v", blockNum),
	)

	index := fmt.Sprintf("%v/%s/%s/%v", handler.Prefix, handler.Username, handler.Filename, blockNum)
	content, err := GuardedRetrieveDS(fileEncKey, fileMacKey, index)
	if err != nil{
		return nil, err
	}
	return content, nil
}


func (handler *File) Load() ([]byte, error){

	content := make([]byte, handler.Size)
	var cnt int = 0

	for i:=0; i<handler.FBC; i++{
		blockContent, err := handler.LoadBlock(i)
		if err != nil{
			return nil, err
		}
		copy(content[cnt:], blockContent)
		cnt += len(blockContent)
	}
	return content, nil
}


func (userdataptr* User) FileMetaUpdate(filename string, updatedMeta *File) error{
	ptr := userdataptr
	var metaMacKey []byte
	var metaEncKey []byte
	var index string

	handler, metaEncKey, metaMacKey, err := ptr.OpenFile(filename)
	if err != nil{
		return err
	}

	index = fmt.Sprintf("%v/%s/%s/Meta", handler.Prefix, handler.Username, handler.Filename)
	GuardedStoreDS(metaEncKey, metaMacKey, index, *updatedMeta)
	return nil
}


/*
	INVITATION
*/

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

func (userdataptr *User) CreateInvitation (filename string, recipientUsername string)(
	invitationPtr uuid.UUID, err error){

	ptr := userdataptr
	_, _, _, err = ptr.OpenFile(filename)
	if err != nil{
		return uuid.UUID{}, errors.New("File sharer does not have access to the file or the file does not exist!")
	}

	metaEncKey, metaMacKey, _ := ptr.__getMenuKey(filename)
	prefix, _ := ptr.__getPrefix(filename)

	// metaEncKey, metaMacKey, _ := ptr.__getMenuKey(filename)
	inv := Invitation{
		MetaBlockUUID: GetUUID(
			fmt.Sprintf("%v/%s/%s/Meta", prefix, ptr.Username, filename),
		),
		MetaMacUUID: GetUUID(
			fmt.Sprintf("%v/%s/%s/Meta/MAC", prefix, ptr.Username, filename),
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



func (userdataptr *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error{
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
	prefix, _ := ptr.__initPrefix(filename)


	GuardedStoreDS(
		metaEncKey, metaMacKey,
		fmt.Sprintf("%v/%s/%s/Meta", prefix, ptr.Username, filename),
		handler,
	)

	// update the AccessList in sharer's meta block
	// AccessList[$recepient] = ("filename", metaEncKey, metaMacKey)

	recipientTuple := RecipientTuple{
		MetaBlockUUID: GetUUID(
			fmt.Sprintf("%v/%s/%s/Meta", prefix, ptr.Username, filename),
		),
		MetaMacUUID: GetUUID(
			fmt.Sprintf("%v/%s/%s/Meta/MAC", prefix, ptr.Username, filename),
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


func (userdataptr *User) RevokeAccess(filename string, recipientUsername string) error{
	ptr := userdataptr
	handler, _, _, _ := ptr.OpenFile(filename)
	newMetaEncKey, newMetaMacKey, _ := ptr.__initMenuKey(filename)

	/*
		1. Re-encrypt meta block and file content
		2. distribute to direct children
		3. Re-generate file prefix
	*/
	var prevHandler File = File{
		Filename: handler.Filename,
		Username: handler.Username,
		Prefix: handler.Prefix,
		GKey: handler.GKey,
	}

	newGKey := userlib.RandomBytes(16)
	handler.GKey = newGKey

	// Re-generate prefix
	newPrefix, _ := ptr.__getPrefix(filename)
	handler.Prefix = newPrefix


	newMetaBlockUUID := GetUUID(
		fmt.Sprintf("%v/%s/%s/Meta", newPrefix, ptr.Username, filename),
	)

	newMetaMacUUID := GetUUID(
		fmt.Sprintf("%v/%s/%s/Meta/MAC", newPrefix, ptr.Username, filename),
	)


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
	for _, recipientTuple := range handler.AccessList{
		var recipientMeta File
		stream, _ := GuardedRetrieveDSUUID(
			recipientTuple.MetaEncKey,
			recipientTuple.MetaMacKey,
			recipientTuple.MetaBlockUUID,
			recipientTuple.MetaMacUUID,
		)
		json.Unmarshal(stream, &recipientMeta)


		recipientMeta.Link.MetaBlockUUID = newMetaBlockUUID
		recipientMeta.Link.MetaMacUUID = newMetaMacUUID
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
		fmt.Sprintf("%v/%s/%s/Meta", newPrefix, ptr.Username, filename),
		handler,
	)
	
	return nil
}







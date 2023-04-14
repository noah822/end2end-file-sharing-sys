package tools

import (
	"fmt"
	"errors"
	"github.com/google/uuid"
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
)

type SoftLink struct {
	// Owner string
	// Filename string
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




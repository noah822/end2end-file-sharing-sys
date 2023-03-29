package tools

import (
	"fmt"
	// "errors"
	"log"
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
)

type SoftLink struct {
	FileOwner string
	FileName string
} 

type File struct {
	// Soft link to another file if necessary, default: nil 
	Linked bool
	Link SoftLink

	Username string
	Filename string
	Size int
	GKey []byte

	// file access privillege control
	AccessList map[string]bool

	// file block count used for efficient file append
	FBC int
}

func (userdataptr *User)CreateFile(filename string, size int) *File {
	ptr := userdataptr
	handler := File{
		Linked: false,
		Username: ptr.Username,
		Filename: filename,
		GKey: userlib.RandomBytes(16),
		AccessList: make(map[string]bool),
		Size: size,
		FBC: 1,
	} 

	/*
		Assign file control block
		encryption and mac key
	*/
	metaEncKey, metaMacKey, _ := ptr.__initMenuKey(filename)
	
	GuardedStoreDS(
		metaEncKey, metaMacKey,
		fmt.Sprintf("%s/%s/Meta", ptr.Username, filename),
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

	var _menu SharedKeyMenu
	json.Unmarshal(stream, &_menu)


	if err != nil{
		panic("Menu has been tampered with!")
	}

	metaEncKey := userlib.RandomBytes(16)
	metaMacKey := userlib.RandomBytes(16)

	_menu.Menu[filename] = metaEncKey
	_menu.Menu[filename + "/MAC"] = metaMacKey

	ptr.EncMacStoreDS("Menu", _menu)

	return metaEncKey, metaMacKey, nil
}

func (userdataptr *User) __getMenuKey(filename string) ([]byte, []byte, error){
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

	metaEncKey := _menu.Menu[filename]
	metaMacKey := _menu.Menu[filename + "/MAC"]

	return metaEncKey, metaMacKey, nil
}



func (userdataptr* User) OpenFile(filename string) *File{
	ptr := userdataptr

	index := fmt.Sprintf("%s/%s/Meta", ptr.Username, filename)

	metaEncKey, metaMacKey, _ := ptr.__getMenuKey(filename)

	var handler File
	stream, err := GuardedRetrieveDS(metaEncKey, metaMacKey, index)
	if err != nil{
		log.Fatal(err)
	}
	json.Unmarshal(stream, &handler)

	return &handler
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
		fmt.Sprintf("%s/%s/%v", handler.Username, handler.Filename, blockNum),
		ctext)

	StoreDS(
		fmt.Sprintf("%s/%s/%v/MAC", handler.Username, handler.Filename, blockNum),
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

	index := fmt.Sprintf("%s/%s/%v", handler.Username, handler.Filename, blockNum)

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
			log.Fatal(err)
			return nil, err
		}
		copy(content[cnt:], blockContent)
		cnt += len(blockContent)
	}
	return content, nil
}


func (userdataptr* User) FileMetaUpdate(filename string, updatedMeta *File) error{
	ptr := userdataptr
	index := fmt.Sprintf("%s/%s/Meta", ptr.Username, filename)
	metaEncKey, metaMacKey, _ := ptr.__getMenuKey(filename)
	GuardedStoreDS(metaEncKey, metaMacKey, index, *updatedMeta)
	return nil
}




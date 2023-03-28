package tools

import (
	"fmt"
	"errors"
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

type FileBlock struct {
	Content []byte
	Mac []byte
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

	metaEncKey, _ := ptr.GetKey(
		fmt.Sprintf("ENC-%s-Meta", filename), 
	)
	StoreDS(
		fmt.Sprintf("%s/%s/Meta", ptr.Username, filename),
		SerThenEnc(metaEncKey, handler),
	)
	return &handler
}

func (userdataptr* User) OpenFile(filename string) *File{
	ptr := userdataptr

	index := fmt.Sprintf("%s/%s/Meta", ptr.Username, filename)
	metaEncKey, _ := ptr.GetKey(
		fmt.Sprintf("ENC-%s-Meta", filename), 
	)

	var handler File
	stream, _ := DecRetrieveDS(metaEncKey, index)
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
	fileBlock := FileBlock {
		Content: ctext,
		Mac: hmac,
	}
	StoreDS(
		fmt.Sprintf("%s/%s/%v", handler.Username, handler.Filename, blockNum),
		SerThenEnc(nil, fileBlock))
	
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

	var block FileBlock
	stream, _ := DecRetrieveDS(nil, index)
	json.Unmarshal(stream, &block)

	correctMac, _ := userlib.HMACEval(fileMacKey, block.Content)
	if !userlib.HMACEqual(block.Mac, correctMac){
		return nil, errors.New(
			fmt.Sprintf("Invalid MAC value, file %s has been tampered!", handler.Filename),
		)
	}else{
		content := userlib.SymDec(fileEncKey, block.Content)
		return content, nil
	}
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
	metaEncKey, _ := ptr.GetKey(
		fmt.Sprintf("ENC-%s-Meta", filename),
	)
	StoreDS(
		index,
		SerThenEnc(metaEncKey, *updatedMeta),
	)
	return nil
}


func (handler *File) Append(content []byte) error {
	/*
		Update file control block
	*/
	handler.FBC++
	handler.Store(handler.FBC, content)

	return nil
	
	/*
		Create New File Block
	*/
}




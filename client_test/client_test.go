package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.

	// "fmt"

	"github.com/google/uuid"
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		
		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Basic Test: CreateInvitation test", func(){
		Specify("Filename does not exist under the namespace of the caller", func(){
			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create invitation on aliceFile for Bob, and Bob accepts it.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("Recipient does not exist", func(){
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create invitation on aliceFile for Bob, but Bob does not exist")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Edge Test: Empty username test", func(){
		Specify("Edge Test: Testing empty username", func(){
			userlib.DebugMsg("Initializing users Alice with empty username")
			alice, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())
			
		})
		
	})

	Describe("Edge Test: Append to non-exist file", func(){
		Specify("Edge Test: Testing empty username", func(){
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte("garbage"))
			Expect(err).ToNot(BeNil())
			
		})
		
	})

	

	Describe("Edge Test: Empty password test", func(){
		Specify("Edge Test: Testing empty password", func(){
			userlib.DebugMsg("Initializing users Alice with default password")
			alice, err = client.InitUser("alice",emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Login users Alice with empty password")
			aliceLaptop, err = client.GetUser("alice", emptyString)
			Expect(err).To(BeNil())
			
		})
	})

	Describe("Edge Test: Case sensitive test", func(){
		Specify("Testing Bob != bob", func(){
			userlib.DebugMsg("Initializing users Bob with default password")
			bob, err = client.InitUser("Bob",defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob with default password")
			alice, err = client.InitUser("bob",defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Login users bob with his password")
			aliceLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
		})
	})

	Describe("Edge Test: Empty file name and content(store/ load/ append)", func(){
		Specify("Should support empty file name", func(){
			userlib.DebugMsg("Initializing users Bob with default password")
			bob, err = client.InitUser("Bob",defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating empty file with empty name")
			err = bob.StoreFile("", []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := bob.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("")))

			userlib.DebugMsg("Appending empty content")
			err = bob.AppendToFile("", []byte(""))
			Expect(err).To(BeNil())
			
		})
	})


	Describe("Edge Test: Login with Incorrect password test", func(){
		Specify("Edge Test: Testing empty username", func(){
			userlib.DebugMsg("Initializing users Alice with default password")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Login users Alice with empty password")
			aliceLaptop, err = client.GetUser("alice", "")
			Expect(err).ToNot(BeNil())
			
		})
	})

	Describe("Edge Test: Login with non-existed account test", func(){
		Specify("Edge Test: Testing empty username", func(){
			// userlib.DebugMsg("Initializing users Alice with empty password")
			// alice, err = client.InitUser("alice", defaultPassword)
			// Expect(err).To(BeNil())

			userlib.DebugMsg("Login un-registed users Alice with password")
			aliceLaptop, err = client.GetUser("alice", "")
			Expect(err).ToNot(BeNil())
			
		})
	})

	Describe("Test: Outdated invitation test", func (){
		Specify("Revoke invitation sharer, before invitation gets accepted", func(){

			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Alice create invitation on aliceFile for Bob, and Bob accepts it.")
			alice_invite_bob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", alice_invite_bob, bobFile)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Bob invites Charles.")
			bob_invite_charles, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Alice revokes Bob. Then invitation from Bob to Charles becomes outdated")

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", bob_invite_charles, charlesFile)
			Expect(err).ToNot(BeNil())

		})

	
	})

	Describe("Unmatched invitation and senderName arg", func() {
		Specify("wrong senderName", func(){
			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Alice create invitation on aliceFile for Bob.")
			alice_invite_bob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			

			userlib.DebugMsg("Bob accepts it with incorrect senderName specified.")
			err = bob.AcceptInvitation("charles", alice_invite_bob, bobFile)
			Expect(err).ToNot(BeNil())		
		})
	}) 


	Describe("Duplicate filename under recipient's namespace", func() {
		Specify("duplicate filename when accept the invitation", func(){
			userlib.DebugMsg("Initializing users Alice, Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create file.txt.")
			err = alice.StoreFile("file.txt", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob create file.txt.")
			err = bob.StoreFile("file.txt", []byte(contentOne))
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Alice create invitation on aliceFile for Bob.")
			alice_invite_bob, err := alice.CreateInvitation("file.txt", "bob")
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Bob accepts it with incorrect senderName specified.")
			err = bob.AcceptInvitation("alice", alice_invite_bob, "file.txt")
			Expect(err).ToNot(BeNil())		
		})
	}) 


	Describe("Revocation sanity check", func() {
		Specify("File revoke does not exist", func(){
			userlib.DebugMsg("Initializing users Alice, Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			
			userlib.DebugMsg("Alice create invitation on aliceFile for Bob.")
			alice_invite_bob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Bob accepts it properly.")
			err = bob.AcceptInvitation("alice", alice_invite_bob, bobFile)
			Expect(err).To(BeNil())		

			userlib.DebugMsg("Alice tries to revoke a file which does not exist under her namespace.")
			err = alice.RevokeAccess("random.txt", "bob")
			Expect(err).ToNot(BeNil())		
		})

		Specify("Recipient to revoke does not exist", func(){
			userlib.DebugMsg("Initializing users Alice, Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			
			userlib.DebugMsg("Alice create invitation on aliceFile for Bob.")
			alice_invite_bob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Bob accepts it properly.")
			err = bob.AcceptInvitation("alice", alice_invite_bob, bobFile)
			Expect(err).To(BeNil())		

			userlib.DebugMsg("Alice tries to revoke charles, who does not exist/have access to the file")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).ToNot(BeNil())		
		})
	}) 


	Describe("Edge case: unaccepted invitation", func(){
		Specify("Unaccepted invitation is still valid after revocation", func(){
			userlib.DebugMsg("Initializing users Alice, Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles",defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

	
			userlib.DebugMsg("Alice create invitation on aliceFile for Bob.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create invitation on aliceFile for Charles.")
			alice_invite_charles, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Alice revoke Bob's access before Bob accepts the invitation")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Make sure invitation for Charles is still valid")
			err = charles.AcceptInvitation("alice", alice_invite_charles, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check Charles can still load the file")
			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})
	})

	Describe("Edge case: unaccepted invitation", func(){
		Specify("Unaccepted invitation Case1", func(){
			userlib.DebugMsg("Initializing users Alice, Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles",defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

	
			userlib.DebugMsg("Alice create invitation on aliceFile for Bob.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create invitation on aliceFile for Charles.")
			alice_invite_charles, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Alice revoke Bob's access before Bob accepts the invitation")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Make sure invitation for Charles is still valid")
			err = charles.AcceptInvitation("alice", alice_invite_charles, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check Charles can still load the file")
			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Unaccepted invitation Case2", func(){
			userlib.DebugMsg("Initializing users Alice, Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles",defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

	
			userlib.DebugMsg("Alice create invitation on aliceFile for Bob.")
			alice_invite_bob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", alice_invite_bob, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create invitation on aliceFile for Charles.")
			alice_invite_charles, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Alice revoke Bob's access after Bob accepts the invitation")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Make sure invitation for Charles is still valid")
			err = charles.AcceptInvitation("alice", alice_invite_charles, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check Charles can still load the file")
			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})
	})



	Describe("Testing on tampering behaviors:", func(){
		//key store
		Specify("Malicious tampering with keystore should be detected.", func() {
			userlib.DebugMsg("Creating user Alice ")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Mallery tries to change public key of alice")
			malleryPK, _, err := userlib.PKEKeyGen()
			Expect(err).To(BeNil())
			keystore := userlib.KeystoreGetMap()
			userlib.KeystoreClear()
			for key := range keystore {
				err = userlib.KeystoreSet(key, malleryPK)
				Expect(err).To(BeNil())
			}

			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		//data store

	})

	Describe("Testing on bandwidth",func(){
		Specify("Bandwidth should be linear to adppeded content!", func(){
			userlib.DebugMsg("Creating user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates a file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bw0 := userlib.DatastoreGetBandwidth()
			

			userlib.DebugMsg("Alice appending the first time")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			bw1 := userlib.DatastoreGetBandwidth()

			userlib.DebugMsg("Alice appending the second time")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			bw2 := userlib.DatastoreGetBandwidth()

			del_1 := bw1-bw0
			del_2 := bw2-bw1
			del_3 := bw2-bw0
			Expect(del_1 == del_2).To(BeTrue())
			Expect(del_1*2 == del_3).To(BeTrue())

		})
		Specify("Appending to file should not take too much bandwith", func() {
			userlib.DebugMsg("Creating user Bob ")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			const CONTENT = `
			2023/04/17 22:00:18 22:00:18.96804 Alice revokes Bob. Then invitation from Bob to Charles becomes outdated
			2023/04/17 22:00:21 22:00:21.60598 Bob accepts it with incorrect senderName specified.
			•2023/04/17 22:00:21 22:00:21.68896 Initializing users Alice, Bob
			2023/04/17 22:00:22 22:00:22.95944 Alice create file.txt.
			2023/04/17 22:00:23 22:00:23.20670 Bob create file.txt.
			2023/04/17 22:00:23 22:00:23.45537 Alice create invitation on aliceFile for Bob.
			2023/04/17 22:00:23 22:00:23.69212 Bob accepts it with incorrect senderName specified.
			•2023/04/17 22:00:23 22:00:23.78208 Initializing users Alice, Bob
			2023/04/17 22:00:25 22:00:25.23358 Alice create aliceFile.txt.
			2023/04/17 22:00:25 22:00:25.45939 Alice create invitation on aliceFile for Bob.
			2023/04/17 22:00:25 22:00:25.72305 Bob accepts it properly.
			2023/04/17 22:00:25 22:00:25.98059 Alice tries to revoke a file which does not exist under her namespace.
			•2023/04/17 22:00:26 22:00:26.02521 Initializing users Alice, Bob
			2023/04/17 22:00:27 22:00:27.32085 Alice create aliceFile.txt.
			2023/04/17 22:00:27 22:00:27.51953 Alice create invitation on aliceFile for Bob.
			2023/04/17 22:00:27 22:00:27.72777 Bob accepts it properly.
			2023/04/17 22:00:27 22:00:27.99760 Alice tries to revoke charles, who does not exist/have access to the file
			•2023/04/17 22:00:28 22:00:28.08049 Initializing users Alice, Bob
			2023/04/17 22:00:29 22:00:29.87911 Alice create aliceFile.txt.
			2023/04/17 22:00:30 22:00:30.07805 Alice create invitation on aliceFile for Bob.
			2023/04/17 22:00:30 22:00:30.29108 Alice create invitation on aliceFile for Charles.
			2023/04/17 22:00:30 22:00:30.49796 Alice revoke Bob's access before Bob accepts the invitation
			2023/04/17 22:00:30 22:00:30.82821 Make sure invitation for Charles is still valid
			2023/04/17 22:00:31 22:00:31.07241 Check Charles can still load the file
			•2023/04/17 22:00:31 22:00:31.15463 Initializing users Alice, Bob
			2023/04/17 22:00:32 22:00:32.84739 Alice create aliceFile.txt.
			`
			const FILENAME = "filename"

			userlib.DatastoreResetBandwidth()
			userlib.DebugMsg("Alice stores a big file")
			err = alice.StoreFile(FILENAME, []byte(CONTENT))
			Expect(err).To(BeNil())

			bandwith0 := userlib.DatastoreGetBandwidth()
			userlib.DatastoreResetBandwidth()

			userlib.DebugMsg("Appending file with little content")
			err = alice.AppendToFile(FILENAME, []byte("."))
			Expect(err).To(BeNil())

			bandwith1 := userlib.DatastoreGetBandwidth()

			Expect(bandwith0 > bandwith1).To(BeTrue())

		})

		

	})

	/*
		Some tampering stuff, including login, invitation, file tampering
	*/

	Describe("DataStore tampering", func() {
		Specify("login tampering", func(){
			userlib.DebugMsg("Initializing Alice, then tamper with DataStore")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			ds := userlib.DatastoreGetMap()		
			for index, _ := range(ds){
				userlib.DatastoreSet(index, []byte("garbage"))
			}
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("file tampering", func(){
			userlib.DebugMsg("Initializing Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			

			var prevDS map[uuid.UUID] []byte = make(map[uuid.UUID][]byte)
			// deep copy datastore
			ds := userlib.DatastoreGetMap()	
			for index, content := range(ds){
				prevDS[index] = content
			}

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())


			var newEntryIndex uuid.UUID
			ds = userlib.DatastoreGetMap()
			for index, _ := range(ds){
				if _, ok := prevDS[index]; !ok{
					newEntryIndex = index
					break
				}
			}
			// Tamper with append content
			userlib.DatastoreSet(newEntryIndex, []byte(""))

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("invitation tampering", func(){
			userlib.DebugMsg("Initializing Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			var prevDS map[uuid.UUID] []byte = make(map[uuid.UUID][]byte)
			// deep copy datastore
			ds := userlib.DatastoreGetMap()	
			for index, content := range(ds){
				prevDS[index] = content
			}

			alice_invite_bob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())


			var newEntryIndex uuid.UUID
			ds = userlib.DatastoreGetMap()
			for index, _ := range(ds){
				if _, ok := prevDS[index]; !ok{
					newEntryIndex = index
					break
				}
			}
			// Tamper with append content
			userlib.DatastoreSet(newEntryIndex, []byte("garbage"))
			
			err = bob.AcceptInvitation("alice", alice_invite_bob, bobFile)
			Expect(err).ToNot(BeNil())
		})

		
	}) 


	Describe("Revoke test", func(){
		Specify("Recipient not revoked can still have access to the file", func(){
			userlib.DebugMsg("Initializing users Alice, Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles",defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create aliceFile.txt.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create invitation on aliceFile for Bob.")
			alice_invite_bob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", alice_invite_bob, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice create invitation on aliceFile for Charles.")
			alice_invite_charles, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Make sure invitation for Charles is still valid")
			err = charles.AcceptInvitation("alice", alice_invite_charles, charlesFile)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check Charles can still load the file")
			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Describe("KS length tests",func(){
			Specify("Legngth of KS should not depend on the number of files",func(){
				userlib.DebugMsg("Creating user Alice ")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				// userlib.DebugMsg("Mallery tries to change public key of alice")
				// malleryPK, _, err := userlib.PKEKeyGen()
				// Expect(err).To(BeNil())
				keystore_pre := userlib.KeystoreGetMap()
				userlib.DebugMsg("Alice creates 2 files ")
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
				err = alice.StoreFile(bobFile, []byte(contentOne))
				Expect(err).To(BeNil())
				keystore_post := userlib.KeystoreGetMap()
				Expect(keystore_pre).To(Equal(keystore_post))
			})

			Specify("Legngth of KS should not depend on the length of file",func(){

				const CONTENT = `
				2023/04/17 22:00:18 22:00:18.96804 Alice revokes Bob. Then invitation from Bob to Charles becomes outdated
				2023/04/17 22:00:21 22:00:21.60598 Bob accepts it with incorrect senderName specified.
				•2023/04/17 22:00:21 22:00:21.68896 Initializing users Alice, Bob
				2023/04/17 22:00:22 22:00:22.95944 Alice create file.txt.
				2023/04/17 22:00:23 22:00:23.20670 Bob create file.txt.
				2023/04/17 22:00:23 22:00:23.45537 Alice create invitation on aliceFile for Bob.
				2023/04/17 22:00:23 22:00:23.69212 Bob accepts it with incorrect senderName specified.
				•2023/04/17 22:00:23 22:00:23.78208 Initializing users Alice, Bob
				2023/04/17 22:00:25 22:00:25.23358 Alice create aliceFile.txt.
				2023/04/17 22:00:25 22:00:25.45939 Alice create invitation on aliceFile for Bob.
				2023/04/17 22:00:25 22:00:25.72305 Bob accepts it properly.
				2023/04/17 22:00:25 22:00:25.98059 Alice tries to revoke a file which does not exist under her namespace.
				•2023/04/17 22:00:26 22:00:26.02521 Initializing users Alice, Bob
				2023/04/17 22:00:27 22:00:27.32085 Alice create aliceFile.txt.
				2023/04/17 22:00:27 22:00:27.51953 Alice create invitation on aliceFile for Bob.
				2023/04/17 22:00:27 22:00:27.72777 Bob accepts it properly.
				2023/04/17 22:00:27 22:00:27.99760 Alice tries to revoke charles, who does not exist/have access to the file
				•2023/04/17 22:00:28 22:00:28.08049 Initializing users Alice, Bob
				2023/04/17 22:00:29 22:00:29.87911 Alice create aliceFile.txt.
				2023/04/17 22:00:30 22:00:30.07805 Alice create invitation on aliceFile for Bob.
				2023/04/17 22:00:30 22:00:30.29108 Alice create invitation on aliceFile for Charles.
				2023/04/17 22:00:30 22:00:30.49796 Alice revoke Bob's access before Bob accepts the invitation
				2023/04/17 22:00:30 22:00:30.82821 Make sure invitation for Charles is still valid
				2023/04/17 22:00:31 22:00:31.07241 Check Charles can still load the file
				•2023/04/17 22:00:31 22:00:31.15463 Initializing users Alice, Bob
				2023/04/17 22:00:32 22:00:32.84739 Alice create aliceFile.txt.
				`
				userlib.DebugMsg("Creating user Alice ")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				// userlib.DebugMsg("Mallery tries to change public key of alice")
				// malleryPK, _, err := userlib.PKEKeyGen()
				// Expect(err).To(BeNil())
			
				userlib.DebugMsg("Alice creates 1 files ")
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
				keystore_pre := userlib.KeystoreGetMap()
				userlib.DebugMsg("Alice appends a lot of contents")
				err = alice.StoreFile(aliceFile, []byte(CONTENT))
				Expect(err).To(BeNil())
				keystore_post := userlib.KeystoreGetMap()
				Expect(keystore_pre).To(Equal(keystore_post))
			})

			Specify("Legngth of KS should not depend on the number of users being invited",func(){
				userlib.DebugMsg("Initializing users Alice, Bob")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())
				
				bob, err = client.InitUser("bob", defaultPassword)
				Expect(err).To(BeNil())

				charles, err = client.InitUser("charles",defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice create aliceFile.txt.")
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				keystore_pre := userlib.KeystoreGetMap()
				userlib.DebugMsg("Alice create invitation on aliceFile for Bob.")
				alice_invite_bob, err := alice.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())

				err = bob.AcceptInvitation("alice", alice_invite_bob, bobFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice create invitation on aliceFile for Charles.")
				alice_invite_charles, err := alice.CreateInvitation(aliceFile, "charles")
				Expect(err).To(BeNil())

				err = charles.AcceptInvitation("alice", alice_invite_charles, charlesFile)
				Expect(err).To(BeNil())
				

				// userlib.DebugMsg("Mallery tries to change public key of alice")
				// malleryPK, _, err := userlib.PKEKeyGen()
				// Expect(err).To(BeNil())
				// keystore_pre := userlib.KeystoreGetMap()
				// userlib.DebugMsg("Alice creates 2 files ")
				// err = alice.StoreFile(aliceFile, []byte(contentOne))
				// Expect(err).To(BeNil())
				// err = alice.StoreFile(bobFile, []byte(contentOne))
				// Expect(err).To(BeNil())
				keystore_post := userlib.KeystoreGetMap()
				Expect(keystore_pre).To(Equal(keystore_post))
			})
			
		})
	})



	



	/* 
		Revoked recipient tampering
	*/
})

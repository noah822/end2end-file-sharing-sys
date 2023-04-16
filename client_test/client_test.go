package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
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
			Expect(del_1 == del_2).To(BeTrue())
		})
	})
})

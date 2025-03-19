package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/oklog/ulid"
)

// OutboundMessage holds the API request data for sending a message.
type OutboundMessage struct {
	YggAddress string `json:"ygg_address"` // Target Yggdrasil address
	Port       int    `json:"port"`        // Target port (e.g., 6969)
	Sender     string `json:"sender"`      // Sender's fingerprint
	Recipient  string `json:"recipient"`   // Recipient's fingerprint
	Timestamp  int64  `json:"timestamp"`   // Unix timestamp
	Content    string `json:"content"`     // The message text
}

var (
	database     *bolt.DB
	messageStore = []OutboundMessage{}
	storeMutex   sync.Mutex

	// myFingerprint holds the server's (or user's) fingerprint.
	myFingerprint string
)

const (
	dbFile     = "database.db"
	bucketName = "conversations" // We'll store messages by conversation ID.
)

// conversationID computes a unique conversation ID from two fingerprints.
func conversationID(fp1, fp2 string) string {
	if fp1 < fp2 {
		return fp1 + "-" + fp2
	}
	return fp2 + "-" + fp1
}

// generateKeyPair creates a new OpenPGP entity.
func generateKeyPair(name, comment, email, passphrase string) (*openpgp.Entity, error) {
	config := &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        time.Now,
		RSABits:     2048,
	}
	entity, err := openpgp.NewEntity(name, comment, email, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create new entity: %w", err)
	}
	if entity.PrivateKey == nil {
		return nil, fmt.Errorf("entity.PrivateKey is nil")
	}
	for idName, id := range entity.Identities {
		log.Printf("Signing identity: %s", idName)
		if err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, config); err != nil {
			return nil, fmt.Errorf("failed to sign identity %s: %w", idName, err)
		}
	}
	if passphrase != "" {
		if err := entity.PrivateKey.Encrypt([]byte(passphrase)); err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil {
				if err := subkey.PrivateKey.Encrypt([]byte(passphrase)); err != nil {
					return nil, fmt.Errorf("failed to encrypt subkey: %w", err)
				}
			}
		}
	}
	return entity, nil
}

// saveKey writes the public and private keys to files.
func saveKey(entity *openpgp.Entity, pubFilename, privFilename string) error {
	// Save public key.
	pubFile, err := os.Create(pubFilename)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubFile.Close()
	armorWriter, err := armor.Encode(pubFile, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("failed to create armor encoder for public key: %w", err)
	}
	if err := entity.Serialize(armorWriter); err != nil {
		return fmt.Errorf("failed to serialize public key: %w", err)
	}
	armorWriter.Close()
	// Save private key.
	privFile, err := os.Create(privFilename)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privFile.Close()
	armorWriter, err = armor.Encode(privFile, openpgp.PrivateKeyType, nil)
	if err != nil {
		return fmt.Errorf("failed to create armor encoder for private key: %w", err)
	}
	if err := entity.SerializePrivate(armorWriter, nil); err != nil {
		return fmt.Errorf("failed to serialize private key: %w", err)
	}
	armorWriter.Close()
	return nil
}

// GenerateAndStoreKeys generates and saves keys.
func GenerateAndStoreKeys(name, comment, email, passphrase, pubFilename, privFilename string) (*openpgp.Entity, error) {
	entity, err := generateKeyPair(name, comment, email, passphrase)
	if err != nil {
		return nil, fmt.Errorf("error generating key pair: %w", err)
	}
	fingerprintStr := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	fmt.Printf("Generated Public Key Fingerprint: %s\n", fingerprintStr)
	if err := saveKey(entity, pubFilename, privFilename); err != nil {
		return nil, fmt.Errorf("error saving keys: %w", err)
	}
	fmt.Println("Key pair generated and saved successfully!")
	return entity, nil
}

// initDatabase initializes BoltDB.
func initDatabase() *bolt.DB {
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Fatalf("Could not open DB: %v", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	})
	if err != nil {
		log.Fatalf("Could not create bucket: %v", err)
	}
	return db
}

// generateULID creates a new ULID string.
func generateULID() string {
	entropy := ulid.Monotonic(rand.Reader, 0)
	id := ulid.MustNew(ulid.Timestamp(time.Now()), entropy)
	return id.String()
}

// saveMessageForConversation stores a message in the conversation bucket.
func saveMessageForConversation(db *bolt.DB, convID string, msg OutboundMessage) error {
	key := []byte(generateULID())
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		convBucket, err := tx.Bucket([]byte(bucketName)).CreateBucketIfNotExists([]byte(convID))
		if err != nil {
			return fmt.Errorf("failed to create/open conversation bucket: %w", err)
		}
		return convBucket.Put(key, data)
	})
}

// getMessagesByConversationHandler returns messages for a conversation.
func getMessagesByConversationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	convID := r.URL.Query().Get("conversation")
	if convID == "" {
		http.Error(w, "Missing conversation parameter", http.StatusBadRequest)
		return
	}
	var messages []OutboundMessage
	err := database.View(func(tx *bolt.Tx) error {
		convBucket := tx.Bucket([]byte(bucketName)).Bucket([]byte(convID))
		if convBucket == nil {
			return nil // No messages yet.
		}
		c := convBucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var msg OutboundMessage
			if err := json.Unmarshal(v, &msg); err != nil {
				log.Printf("Error unmarshaling message: %v", err)
				continue
			}
			messages = append(messages, msg)
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

// deleteConversationHandler deletes a conversation bucket.
func deleteConversationHandler(w http.ResponseWriter, r *http.Request) {
	// Handle preflight OPTIONS request.
	if enableCORSHTTP(w, r) {
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	convID := r.URL.Query().Get("conversation")
	if convID == "" {
		http.Error(w, "Missing conversation parameter", http.StatusBadRequest)
		return
	}
	err := database.Update(func(tx *bolt.Tx) error {
		parent := tx.Bucket([]byte(bucketName))
		if parent == nil {
			return fmt.Errorf("bucket %q not found", bucketName)
		}
		return parent.DeleteBucket([]byte(convID))
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "Conversation deleted successfully"})
}

// getFingerprintsHandler returns all conversation IDs.
func getFingerprintsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	var convIDs []string
	err := database.View(func(tx *bolt.Tx) error {
		convBucket := tx.Bucket([]byte(bucketName))
		if convBucket == nil {
			return fmt.Errorf("bucket %q not found", bucketName)
		}
		return convBucket.ForEach(func(k, v []byte) error {
			if v == nil {
				convIDs = append(convIDs, string(k))
			}
			return nil
		})
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(convIDs)
}

// getMyFingerprintHandler returns the server's fingerprint.
func getMyFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"fingerprint": myFingerprint,
	})
}

// enableCORSHTTP handles CORS preflight.
func enableCORSHTTP(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

// readAndIndentBodyHTTP reads and formats the body.
func readAndIndentBodyHTTP(r *http.Request) ([]byte, string, error) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, "", err
	}
	defer r.Body.Close()
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, bodyBytes, "", "  "); err != nil {
		return bodyBytes, "", err
	}
	return bodyBytes, pretty.String(), nil
}

// sendMessageToPeer forwards a message over TCP.
func sendMessageToPeer(msg OutboundMessage) error {
	address := fmt.Sprintf("%s:%d", msg.YggAddress, msg.Port)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("error dialing %s: %w", address, err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		return fmt.Errorf("error sending message to peer: %w", err)
	}
	log.Printf("Successfully forwarded message to %s", address)
	return nil
}

// sendMessageHandler handles /sendMessage requests.
func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if enableCORSHTTP(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, prettyBody, err := readAndIndentBodyHTTP(r)
	if err != nil {
		log.Printf("API: Error reading request body: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	log.Printf("API: Received request body (pretty):\n%s", prettyBody)
	var msg OutboundMessage
	if err := json.Unmarshal(bodyBytes, &msg); err != nil {
		log.Printf("API: Error decoding JSON: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().Unix()
	}
	log.Printf("API: Message to send: %+v", msg)
	storeMutex.Lock()
	messageStore = append(messageStore, msg)
	storeMutex.Unlock()
	convID := conversationID(msg.Sender, msg.Recipient)
	if err := saveMessageForConversation(database, convID, msg); err != nil {
		log.Printf("API: Error saving message: %v", err)
	}
	if err := sendMessageToPeer(msg); err != nil {
		log.Printf("API: Error forwarding message to peer: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Message sent successfully",
	})
}

// handleCommConnection processes incoming TCP connections.
func handleCommConnection(conn net.Conn) {
	defer conn.Close()
	bodyBytes, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Printf("Comm Server: Error reading from connection: %v", err)
		return
	}
	var msg OutboundMessage
	if err := json.Unmarshal(bodyBytes, &msg); err != nil {
		log.Printf("Comm Server: Error decoding JSON: %v", err)
		log.Printf("Comm Server: Raw data: %s", string(bodyBytes))
		return
	}
	log.Printf("Comm Server: Received Message")
	log.Printf("  Sender: %s", msg.Sender)
	log.Printf("  Recipient: %s", msg.Recipient)
	log.Printf("  Content: %s", msg.Content)
	log.Printf("  Address: %s", msg.YggAddress)
	log.Printf("  Time: %s", time.Unix(msg.Timestamp, 0).Format(time.RFC1123))
	convID := conversationID(msg.Sender, msg.Recipient)
	if err := saveMessageForConversation(database, convID, msg); err != nil {
		log.Printf("Error saving message to DB: %v", err)
	}
}

// runRESTServer starts the REST API server.
func runRESTServer(port string) {
	http.HandleFunc("/sendMessage", sendMessageHandler)
	http.HandleFunc("/getMessages", getMessagesByConversationHandler)
	http.HandleFunc("/getFingerprints", getFingerprintsHandler)
	http.HandleFunc("/getMyFingerprint", getMyFingerprintHandler)
	http.HandleFunc("/deleteConversation", deleteConversationHandler)
	log.Printf("REST API server listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// runCommServer starts the TCP server.
func runCommServer(port string) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Comm Server: Error binding to port %s: %v", port, err)
	}
	defer listener.Close()
	log.Printf("Comm Server: Listening on port %s", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Comm Server: Error accepting connection: %v", err)
			continue
		}
		go handleCommConnection(conn)
	}
}

func main() {
	fmt.Println("[?] Do you have a pub and priv key already created (Y/N): ")
	var answer string
	fmt.Scan(&answer)
	var entity *openpgp.Entity
	if answer == "N" {
		var err error
		entity, err = GenerateAndStoreKeys("test", "P2P Messenger Key", "test@example.com", "", "public.asc", "private.asc")
		if err != nil {
			log.Fatalf("Error generating keys: %v", err)
		}
		myFingerprint = fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	} else {
		pubFile, err := os.Open("public.asc")
		if err != nil {
			log.Fatalf("Error opening public key file: %v", err)
		}
		defer pubFile.Close()
		keyRing, err := openpgp.ReadArmoredKeyRing(pubFile)
		if err != nil {
			log.Fatalf("Error reading armored key ring: %v", err)
		}
		if len(keyRing) == 0 {
			log.Fatal("No keys found in public.asc")
		}
		myFingerprint = fmt.Sprintf("%X", keyRing[0].PrimaryKey.Fingerprint)
		fmt.Printf("Loaded fingerprint from public.asc: %s\n", myFingerprint)
	}
	database = initDatabase()
	defer database.Close()
	go runRESTServer("8080")
	runCommServer("6969")
}

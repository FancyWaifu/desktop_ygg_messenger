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
	"path/filepath"
	"strconv"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/oklog/ulid"
)

// ---------------------
// Data Structures
// ---------------------

// OutboundMessage holds the API request data for sending a message.
type OutboundMessage struct {
	YggAddress string `json:"ygg_address"` // Target Yggdrasil address
	Port       int    `json:"port"`        // Target port (e.g., 6969)
	Sender     string `json:"sender"`      // Sender's fingerprint
	Recipient  string `json:"recipient"`   // Recipient's fingerprint
	Timestamp  int64  `json:"timestamp"`   // Unix timestamp
	Content    string `json:"content"`     // The (encrypted) message text
}

// ---------------------
// Global Variables and Constants
// ---------------------

var (
	database     *bolt.DB
	messageStore = []OutboundMessage{}
	storeMutex   sync.Mutex

	myFingerprint string          // Local user's fingerprint
	senderEntity  *openpgp.Entity // Local user's key pair
)

const (
	dbFile     = "data/database.db" // Database path in data directory
	bucketName = "conversations"    // BoltDB bucket name for conversations
	keysDir    = "keys"             // Directory to store key files
)

// ---------------------
// Utility Functions and Middleware
// ---------------------

// withCORS is a simple middleware to set CORS headers.
func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		h(w, r)
	}
}

// saveKeyToFile writes the key data to a file in the keys directory.
func saveKeyToFile(fingerprint, keyData string) error {
	filename := filepath.Join(keysDir, fingerprint+".asc")
	return ioutil.WriteFile(filename, []byte(keyData), 0644)
}

// readAndIndentBodyHTTP reads and pretty-prints the request body.
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

// generateULID creates a new ULID string.
func generateULID() string {
	entropy := ulid.Monotonic(rand.Reader, 0)
	id := ulid.MustNew(ulid.Timestamp(time.Now()), entropy)
	return id.String()
}

// conversationID computes a unique conversation ID from two fingerprints.
func conversationID(fp1, fp2 string) string {
	if fp1 < fp2 {
		return fp1 + "-" + fp2
	}
	return fp2 + "-" + fp1
}

// initDatabase initializes the BoltDB database.
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

// ---------------------
// Key and Cryptography Functions
// ---------------------

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

// GenerateAndStoreKeys generates keys and saves them.
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

// encryptAndSignMessage encrypts a message using the recipient's public key and signs it with the sender's private key.
func encryptAndSignMessage(plaintext string, recipientEntity *openpgp.Entity, senderEntity *openpgp.Entity) (string, error) {
	var buf bytes.Buffer
	w, err := openpgp.Encrypt(&buf, []*openpgp.Entity{recipientEntity}, senderEntity, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write([]byte(plaintext))
	if err != nil {
		return "", err
	}
	w.Close()
	return buf.String(), nil
}

// decryptAndVerifyMessage decrypts a message using the recipient's private key and verifies the signature.
func decryptAndVerifyMessage(ciphertext string, recipientEntity *openpgp.Entity) (string, error) {
	buf := bytes.NewBufferString(ciphertext)
	md, err := openpgp.ReadMessage(buf, openpgp.EntityList{recipientEntity}, nil, nil)
	if err != nil {
		return "", err
	}
	decrypted, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	if md.SignatureError != nil {
		return "", fmt.Errorf("signature verification error: %v", md.SignatureError)
	}
	return string(decrypted), nil
}

// getPublicKeyForFingerprint loads a public key from the keys directory.
func getPublicKeyForFingerprint(fingerprint string) (*openpgp.Entity, error) {
	filename := filepath.Join(keysDir, fingerprint+".asc")
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entities, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, err
	}
	if len(entities) == 0 {
		return nil, fmt.Errorf("no public key found in %s", filename)
	}
	return entities[0], nil
}

// ---------------------
// Custom Keyserver Endpoints
// ---------------------

// uploadKeyHandler allows clients to upload a public key.
func uploadKeyHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Fingerprint string `json:"fingerprint"`
		PublicKey   string `json:"publicKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if payload.Fingerprint == "" || payload.PublicKey == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}
	if err := saveKeyToFile(payload.Fingerprint, payload.PublicKey); err != nil {
		http.Error(w, "Failed to store public key", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Public key uploaded successfully",
	})
}

// getKeyHandler retrieves a public key based on the fingerprint.
func getKeyHandler(w http.ResponseWriter, r *http.Request) {
	fingerprint := r.URL.Query().Get("fingerprint")
	if fingerprint == "" {
		http.Error(w, "Missing fingerprint parameter", http.StatusBadRequest)
		return
	}
	filename := filepath.Join(keysDir, fingerprint+".asc")
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(data)
}

// ---------------------
// P2P Messenger Endpoints
// ---------------------

// saveMessageForConversation stores a message in the BoltDB bucket.
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
	convID := r.URL.Query().Get("conversation")
	if convID == "" {
		http.Error(w, "Missing conversation parameter", http.StatusBadRequest)
		return
	}
	var messages []OutboundMessage
	err := database.View(func(tx *bolt.Tx) error {
		convBucket := tx.Bucket([]byte(bucketName)).Bucket([]byte(convID))
		if convBucket == nil {
			return nil
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

// sendMessageHandler handles message sending: it encrypts, stores, and forwards the message.
func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	bodyBytes, prettyBody, err := readAndIndentBodyHTTP(r)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	log.Printf("Message request:\n%s", prettyBody)
	var msg OutboundMessage
	if err := json.Unmarshal(bodyBytes, &msg); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().Unix()
	}
	recipientEntity, err := getPublicKeyForFingerprint(msg.Recipient)
	if err != nil {
		log.Printf("Error loading recipient public key: %v", err)
		http.Error(w, "Error loading recipient public key", http.StatusInternalServerError)
		return
	}
	encryptedContent, err := encryptAndSignMessage(msg.Content, recipientEntity, senderEntity)
	if err != nil {
		http.Error(w, "Error encrypting message", http.StatusInternalServerError)
		return
	}
	msg.Content = encryptedContent

	storeMutex.Lock()
	messageStore = append(messageStore, msg)
	storeMutex.Unlock()

	convID := conversationID(msg.Sender, msg.Recipient)
	if err := saveMessageForConversation(database, convID, msg); err != nil {
		log.Printf("Error saving message: %v", err)
	}
	if err := sendMessageToPeer(msg); err != nil {
		http.Error(w, "Error forwarding message", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Message sent successfully",
	})
}

// sendMessageToPeer forwards a message over TCP.
func sendMessageToPeer(msg OutboundMessage) error {
	address := net.JoinHostPort(msg.YggAddress, strconv.Itoa(msg.Port))
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("error dialing %s: %w", address, err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		return fmt.Errorf("error sending message to peer: %w", err)
	}
	log.Printf("Forwarded message to %s", address)
	return nil
}

// getMyFingerprintHandler returns the local server's fingerprint.
func getMyFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"fingerprint": myFingerprint,
	})
}

// deleteConversationHandler deletes a conversation bucket.
func deleteConversationHandler(w http.ResponseWriter, r *http.Request) {
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
	json.NewEncoder(w).Encode(map[string]string{"status": "Conversation deleted successfully"})
}

// getFingerprintsHandler returns all conversation IDs.
func getFingerprintsHandler(w http.ResponseWriter, r *http.Request) {
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
	json.NewEncoder(w).Encode(convIDs)
}

// ---------------------
// TCP Communication
// ---------------------

// handleCommConnection processes incoming TCP messages.
func handleCommConnection(conn net.Conn) {
	defer conn.Close()
	bodyBytes, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}
	var msg OutboundMessage
	if err := json.Unmarshal(bodyBytes, &msg); err != nil {
		log.Printf("Error decoding JSON from connection: %v", err)
		return
	}
	log.Printf("Received TCP message from %s", msg.Sender)
	decrypted, err := decryptAndVerifyMessage(msg.Content, senderEntity)
	if err != nil {
		log.Printf("Error decrypting message: %v", err)
		return
	}
	msg.Content = decrypted
	convID := conversationID(msg.Sender, msg.Recipient)
	if err := saveMessageForConversation(database, convID, msg); err != nil {
		log.Printf("Error saving message: %v", err)
	}
}

// ---------------------
// Server Startup
// ---------------------

// runRESTServer starts the REST API server with keyserver and messenger endpoints.
func runRESTServer(port string) {
	// Keyserver endpoints.
	http.HandleFunc("/keyserver/uploadKey", withCORS(uploadKeyHandler))
	http.HandleFunc("/keyserver/getKey", withCORS(getKeyHandler))
	// Messenger endpoints.
	http.HandleFunc("/sendMessage", withCORS(sendMessageHandler))
	http.HandleFunc("/getMessages", withCORS(getMessagesByConversationHandler))
	http.HandleFunc("/getFingerprints", withCORS(getFingerprintsHandler))
	http.HandleFunc("/getMyFingerprint", withCORS(getMyFingerprintHandler))
	http.HandleFunc("/deleteConversation", withCORS(deleteConversationHandler))
	log.Printf("REST API server listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// runCommServer starts a TCP server for peer messaging.
func runCommServer(port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Error starting TCP server: %v", err)
	}
	log.Printf("TCP Comm server listening on :%s", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleCommConnection(conn)
	}
}

// ---------------------
// Main Function
// ---------------------

func main() {
	// Ensure keys directory exists.
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		if err := os.MkdirAll(keysDir, 0755); err != nil {
			log.Fatalf("Failed to create keys directory: %v", err)
		}
	}
	// Ensure data directory exists.
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		if err := os.MkdirAll("data", 0755); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}
	}

	fmt.Println("[?] Do you have a pub and priv key already created (Y/N): ")
	var answer string
	fmt.Scan(&answer)
	if answer == "N" {
		entity, err := GenerateAndStoreKeys("test", "P2P Messenger Key", "test@example.com", "",
			filepath.Join(keysDir, "public.asc"),
			filepath.Join(keysDir, "private.asc"))
		if err != nil {
			log.Fatalf("Error generating keys: %v", err)
		}
		myFingerprint = fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
		senderEntity = entity
	} else {
		pubFile, err := os.Open(filepath.Join(keysDir, "public.asc"))
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
		fmt.Printf("Loaded fingerprint from keys/public.asc: %s\n", myFingerprint)
		senderEntity = keyRing[0]
	}

	database = initDatabase()
	defer database.Close()

	// Run REST API (keyserver and messenger endpoints) on port 8080.
	go runRESTServer("8080")
	// Run TCP server for P2P messaging on port 6969.
	runCommServer("6969")
}

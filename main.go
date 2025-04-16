package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
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

type OutboundMessage struct {
	YggAddress string `json:"ygg_address"`
	Port       int    `json:"port"`
	Sender     string `json:"sender"`
	Recipient  string `json:"recipient"`
	Timestamp  int64  `json:"timestamp"`
	Content    string `json:"content"`
}

// ---------------------
// Global Variables and Constants
// ---------------------

var (
	database     *bolt.DB
	messageStore = []OutboundMessage{}
	storeMutex   sync.Mutex

	myFingerprint string          // Local user's fingerprint
	senderEntity  *openpgp.Entity // Local user's key pair (must include the private key for decryption)
)

var (
	authToken        string               // Loaded from environment variable (or fallback)
	dbFile           = "data/database.db" // BoltDB database path
	bucketName       = "conversations"    // Bucket name
	keysDir          = "keys"             // Directory for key files
	maxRequests      = 60                 // Max requests per minute per IP
	bypassEncryption bool                 // For testing: bypass encryption/signing when sending messages
)

// ---------------------
// Middleware Functions
// ---------------------

func withLogging(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[REQUEST] %s %s from %s", r.Method, r.URL.String(), r.RemoteAddr)
		h(w, r)
	}
}

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			log.Printf("[CORS] OPTIONS request, returning 200")
			return
		}
		h(w, r)
	}
}

func withAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer "+authToken {
			log.Printf("[AUTH] Unauthorized access attempt from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

var (
	rateLimitMutex sync.Mutex
	requestCounts  = make(map[string]int)
)

func withRateLimit(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		rateLimitMutex.Lock()
		count := requestCounts[ip]
		if count >= maxRequests {
			rateLimitMutex.Unlock()
			log.Printf("[RATE LIMIT] Too many requests from %s", ip)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		requestCounts[ip] = count + 1
		rateLimitMutex.Unlock()
		h(w, r)
	}
}

func resetRateLimiter() {
	for {
		time.Sleep(time.Minute)
		rateLimitMutex.Lock()
		requestCounts = make(map[string]int)
		rateLimitMutex.Unlock()
		log.Println("[RATE LIMIT] Reset rate limiter")
	}
}

// ---------------------
// Utility Functions
// ---------------------

func saveKeyToFile(fingerprint, keyData string) error {
	filename := filepath.Join(keysDir, fingerprint+".asc")
	log.Printf("[SAVE KEY] Writing key to %s", filename)
	return os.WriteFile(filename, []byte(keyData), 0644)
}

func readAndIndentBodyHTTP(r *http.Request) ([]byte, string, error) {
	bodyBytes, err := io.ReadAll(r.Body)
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

func generateULID() string {
	entropy := ulid.Monotonic(rand.Reader, 0)
	id := ulid.MustNew(ulid.Timestamp(time.Now()), entropy)
	return id.String()
}

func conversationID(fp1, fp2 string) string {
	if fp1 < fp2 {
		return fp1 + "-" + fp2
	}
	return fp2 + "-" + fp1
}

func initDatabase() *bolt.DB {
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Fatalf("[DB] Could not open DB: %v", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			log.Printf("[DB] Could not create bucket: %v", err)
		}
		return err
	})
	if err != nil {
		log.Fatalf("[DB] Could not create bucket: %v", err)
	}
	log.Println("[DB] Database initialized")
	return db
}

// ---------------------
// Key and Cryptography Functions
// ---------------------

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
		log.Printf("[KEY GEN] Signing identity: %s", idName)
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

func saveKey(entity *openpgp.Entity, pubFilename, privFilename string) error {
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
	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor writer for public key: %w", err)
	}

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
	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor writer for private key: %w", err)
	}

	return nil
}

func GenerateAndStoreKeys(name, comment, email, passphrase, pubFilename, privFilename string) (*openpgp.Entity, error) {
	entity, err := generateKeyPair(name, comment, email, passphrase)
	if err != nil {
		return nil, fmt.Errorf("error generating key pair: %w", err)
	}
	fingerprintStr := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	log.Printf("[KEY GEN] Generated Public Key Fingerprint: %s", fingerprintStr)
	if err := saveKey(entity, pubFilename, privFilename); err != nil {
		return nil, fmt.Errorf("error saving keys: %w", err)
	}
	log.Println("[KEY GEN] Key pair generated and saved successfully!")
	return entity, nil
}

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
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("error closing encryption writer: %w", err)
	}
	return buf.String(), nil
}

func decryptAndVerifyMessage(ciphertext string, recipientEntity *openpgp.Entity) (string, error) {
	buf := bytes.NewBufferString(ciphertext)
	md, err := openpgp.ReadMessage(buf, openpgp.EntityList{recipientEntity}, nil, nil)
	if err != nil {
		return "", err
	}
	decrypted, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	if md.SignatureError != nil {
		return "", fmt.Errorf("signature verification error: %v", md.SignatureError)
	}
	return string(decrypted), nil
}

func getPublicKeyForFingerprint(fingerprint string) (*openpgp.Entity, error) {
	// For encryption, a public key is sufficient.
	// If the fingerprint matches the local key, use our public.asc.
	if fingerprint == myFingerprint {
		filename := filepath.Join(keysDir, "public.asc")
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
// Custom Keyserver and Contact Management Endpoints
// ---------------------

func uploadKeyHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Fingerprint string `json:"fingerprint"`
		PublicKey   string `json:"publicKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("[UPLOAD KEY] Error decoding request: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if payload.Fingerprint == "" || payload.PublicKey == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}
	if err := saveKeyToFile(payload.Fingerprint, payload.PublicKey); err != nil {
		log.Printf("[UPLOAD KEY] Error saving key: %v", err)
		http.Error(w, "Failed to store public key", http.StatusInternalServerError)
		return
	}
	log.Printf("[UPLOAD KEY] Key for %s stored", payload.Fingerprint)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Public key uploaded successfully",
	})
}

func getKeyHandler(w http.ResponseWriter, r *http.Request) {
	fingerprint := r.URL.Query().Get("fingerprint")
	if fingerprint == "" {
		http.Error(w, "Missing fingerprint parameter", http.StatusBadRequest)
		return
	}
	filename := filepath.Join(keysDir, fingerprint+".asc")
	data, err := os.ReadFile(filename)
	if err != nil {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}
	log.Printf("[GET KEY] Returning key for %s", fingerprint)
	w.Header().Set("Content-Type", "text/plain")
	w.Write(data)
}

func getMyPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	pubFile, err := os.Open(filepath.Join(keysDir, "public.asc"))
	if err != nil {
		http.Error(w, "Public key not found", http.StatusNotFound)
		return
	}
	defer pubFile.Close()
	keyData, err := io.ReadAll(pubFile)
	if err != nil {
		http.Error(w, "Error reading public key", http.StatusInternalServerError)
		return
	}
	log.Println("[GET MY KEY] Returning own public key")
	w.Header().Set("Content-Type", "text/plain")
	w.Write(keyData)
}

func fetchPublicKeyFromPeer(yggAddress string, port int) (string, error) {
	url := fmt.Sprintf("http://%s:8080/getMyPublicKey", yggAddress)
	log.Printf("[FETCH KEY] Fetching key from %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching public key from peer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-OK response: %d", resp.StatusCode)
	}
	keyData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading public key response: %w", err)
	}
	return string(keyData), nil
}

func addContactHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		YggAddress string `json:"ygg_address"`
		Port       int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("[ADD CONTACT] Error decoding request: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if payload.YggAddress == "" || payload.Port == 0 {
		http.Error(w, "Missing ygg_address or port", http.StatusBadRequest)
		return
	}
	keyData, err := fetchPublicKeyFromPeer(payload.YggAddress, payload.Port)
	if err != nil {
		log.Printf("[ADD CONTACT] Error fetching key: %v", err)
		http.Error(w, fmt.Sprintf("Failed to fetch public key: %v", err), http.StatusInternalServerError)
		return
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(keyData))
	if err != nil || len(entities) == 0 {
		http.Error(w, "Invalid public key data", http.StatusInternalServerError)
		return
	}
	fingerprint := fmt.Sprintf("%X", entities[0].PrimaryKey.Fingerprint)
	if err := saveKeyToFile(fingerprint, keyData); err != nil {
		http.Error(w, "Failed to store public key", http.StatusInternalServerError)
		return
	}
	log.Printf("[ADD CONTACT] Retrieved and stored key with fingerprint %s", fingerprint)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "success",
		"fingerprint": fingerprint,
		"message":     "Public key retrieved and stored successfully",
	})
}

// ---------------------
// P2P Messenger Endpoints
// ---------------------

func saveMessageForConversation(db *bolt.DB, convID string, msg OutboundMessage) error {
	key := []byte(generateULID())
	if len(key) == 0 {
		log.Printf("[SAVE MESSAGE] Generated ULID is empty")
		return fmt.Errorf("invalid ULID")
	}
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[SAVE MESSAGE] Error marshaling message: %v", err)
		return err
	}
	log.Printf("[SAVE MESSAGE] Generated key: %s for conversation %s", key, convID)
	err = db.Update(func(tx *bolt.Tx) error {
		parentBucket := tx.Bucket([]byte(bucketName))
		if parentBucket == nil {
			log.Printf("[SAVE MESSAGE] Parent bucket '%s' not found", bucketName)
			return fmt.Errorf("bucket %q not found", bucketName)
		}
		convBucket, err := parentBucket.CreateBucketIfNotExists([]byte(convID))
		if err != nil {
			log.Printf("[SAVE MESSAGE] Failed to create/open conversation bucket '%s': %v", convID, err)
			return err
		}
		if err := convBucket.Put(key, data); err != nil {
			log.Printf("[SAVE MESSAGE] Failed to store message: %v", err)
			return err
		}
		log.Printf("[SAVE MESSAGE] Message saved under conversation '%s' with key %s", convID, key)
		return nil
	})
	if err != nil {
		log.Printf("[SAVE MESSAGE] db.Update error: %v", err)
	} else {
		log.Printf("[SAVE MESSAGE] Update transaction committed successfully for conversation %s", convID)
	}
	return err
}

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
				log.Printf("[GET MESSAGES] Error unmarshaling message: %v", err)
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
	log.Printf("[GET MESSAGES] Returning %d messages", len(messages))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	bodyBytes, prettyBody, err := readAndIndentBodyHTTP(r)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	log.Printf("[SEND MESSAGE] Request body:\n%s", prettyBody)
	var msg OutboundMessage
	if err := json.Unmarshal(bodyBytes, &msg); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().Unix()
	}

	// Special-case: if sending to yourself, bypass encryption and TCP forwarding.
	if msg.Sender == msg.Recipient {
		log.Printf("[SEND MESSAGE] Self message detected - bypassing encryption and TCP forwarding")
		// In this case, we treat the message as plaintext.
		// Save directly into the database.
		convID := conversationID(msg.Sender, msg.Recipient)
		log.Printf("[SEND MESSAGE] Saving self-message for conversation %s", convID)
		if err := saveMessageForConversation(database, convID, msg); err != nil {
			log.Printf("[SEND MESSAGE] Error saving self-message for conversation %s: %v", convID, err)
		} else {
			log.Printf("[SEND MESSAGE] Self-message saved successfully for conversation %s", convID)
		}
		storeMutex.Lock()
		messageStore = append(messageStore, msg)
		storeMutex.Unlock()
		log.Printf("[SEND MESSAGE] Self-message processed successfully")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "Message sent successfully (self message)",
		})
		return
	}

	// If not a self message, choose whether to bypass encryption based on the test flag.
	if bypassEncryption {
		log.Printf("[SEND MESSAGE] Bypassing encryption; storing plaintext")
		msg.Content = "[PLAIN] " + msg.Content
	} else {
		recipientEntity, err := getPublicKeyForFingerprint(msg.Recipient)
		if err != nil {
			log.Printf("[SEND MESSAGE] Error loading recipient public key: %v", err)
			http.Error(w, "Error loading recipient public key", http.StatusInternalServerError)
			return
		}
		encryptedContent, err := encryptAndSignMessage(msg.Content, recipientEntity, senderEntity)
		if err != nil {
			http.Error(w, "Error encrypting message", http.StatusInternalServerError)
			return
		}
		msg.Content = encryptedContent
	}

	convID := conversationID(msg.Sender, msg.Recipient)
	log.Printf("[SEND MESSAGE] Saving message for conversation %s", convID)
	if err := saveMessageForConversation(database, convID, msg); err != nil {
		log.Printf("[SEND MESSAGE] Error saving message for conversation %s: %v", convID, err)
	} else {
		log.Printf("[SEND MESSAGE] Successfully saved message for conversation %s", convID)
	}

	storeMutex.Lock()
	messageStore = append(messageStore, msg)
	storeMutex.Unlock()

	// Forward the message via TCP for normal (non-self) messages.
	if err := sendMessageToPeer(msg); err != nil {
		http.Error(w, "Error forwarding message", http.StatusInternalServerError)
		return
	}
	log.Printf("[SEND MESSAGE] Message sent successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "Message sent successfully",
	})
}

func sendMessageToPeer(msg OutboundMessage) error {
	address := net.JoinHostPort(msg.YggAddress, strconv.Itoa(msg.Port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("error dialing %s: %w", address, err)
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		return fmt.Errorf("error sending message to peer: %w", err)
	}
	log.Printf("[TCP] Forwarded message to %s", address)
	return nil
}

func getMyFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[GET MY FINGERPRINT] Returning fingerprint: %s", myFingerprint)
	json.NewEncoder(w).Encode(map[string]string{"fingerprint": myFingerprint})
}

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
	log.Printf("[DELETE CONVERSATION] Deleted conversation %s", convID)
	json.NewEncoder(w).Encode(map[string]string{"status": "Conversation deleted successfully"})
}

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
	log.Printf("[GET FINGERPRINTS] Found %d conversations", len(convIDs))
	json.NewEncoder(w).Encode(convIDs)
}

// ---------------------
// TCP Communication
// ---------------------

func handleCommConnection(conn net.Conn) {
	defer conn.Close()
	bodyBytes, err := io.ReadAll(conn)
	if err != nil {
		log.Printf("[TCP] Error reading from connection: %v", err)
		return
	}
	var msg OutboundMessage
	if err := json.Unmarshal(bodyBytes, &msg); err != nil {
		log.Printf("[TCP] Error decoding JSON: %v", err)
		return
	}
	log.Printf("[TCP] Received message from %s", msg.Sender)
	if bypassEncryption {
		log.Printf("[TCP] Bypassing decryption as bypassEncryption is enabled")
	} else {
		decrypted, err := decryptAndVerifyMessage(msg.Content, senderEntity)
		if err != nil {
			log.Printf("[TCP] Error decrypting message: %v", err)
			return
		}
		msg.Content = decrypted
	}
	convID := conversationID(msg.Sender, msg.Recipient)
	if err := saveMessageForConversation(database, convID, msg); err != nil {
		log.Printf("[TCP] Error saving message for conversation %s: %v", convID, err)
	}
}

func runRESTServer(port string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/keyserver/uploadKey", withLogging(withCORS(uploadKeyHandler)))
	mux.HandleFunc("/keyserver/getKey", withLogging(withCORS(getKeyHandler)))
	mux.HandleFunc("/getMyPublicKey", withLogging(withCORS(getMyPublicKeyHandler)))
	mux.HandleFunc("/addContact", withLogging(withCORS(withAuth(withRateLimit(addContactHandler)))))
	mux.HandleFunc("/sendMessage", withLogging(withCORS(withAuth(withRateLimit(sendMessageHandler)))))
	mux.HandleFunc("/getMessages", withLogging(withCORS(withAuth(withRateLimit(getMessagesByConversationHandler)))))
	mux.HandleFunc("/getFingerprints", withLogging(withCORS(withAuth(withRateLimit(getFingerprintsHandler)))))
	mux.HandleFunc("/getMyFingerprint", withLogging(withCORS(withAuth(getMyFingerprintHandler))))
	mux.HandleFunc("/deleteConversation", withLogging(withCORS(withAuth(deleteConversationHandler))))

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	go func() {
		log.Printf("[SERVER] REST API server listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[SERVER] REST server error: %v", err)
		}
	}()
	return srv
}

func runCommServer(port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("[TCP] Error starting TCP server: %v", err)
	}
	log.Printf("[TCP] Comm server listening on :%s", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[TCP] Error accepting connection: %v", err)
			continue
		}
		go handleCommConnection(conn)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Parse command-line flags.
	generateKeys := flag.Bool("genkeys", false, "Generate a new key pair")
	flag.BoolVar(&bypassEncryption, "bypassEncryption", false, "Bypass encryption/signing when sending messages (for testing)")
	flag.Parse()

	// Load configuration.
	authToken = os.Getenv("AUTH_TOKEN")
	if authToken == "" {
		authToken = "my-secret-token"
		log.Println("[CONFIG] AUTH_TOKEN not set. Using default token.")
	}

	// Ensure necessary directories exist.
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		if err := os.MkdirAll(keysDir, 0755); err != nil {
			log.Fatalf("[INIT] Failed to create keys directory: %v", err)
		}
	}
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		if err := os.MkdirAll("data", 0755); err != nil {
			log.Fatalf("[INIT] Failed to create data directory: %v", err)
		}
	}

	// Use -genkeys to create new keys.
	if *generateKeys {
		entity, err := GenerateAndStoreKeys("test", "P2P Messenger Key", "test@example.com", "",
			filepath.Join(keysDir, "public.asc"),
			filepath.Join(keysDir, "private.asc"))
		if err != nil {
			log.Fatalf("[KEY GEN] Error generating keys: %v", err)
		}
		myFingerprint = fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
		senderEntity = entity
	} else {
		// Load the private key so that decryption will work.
		privFile, err := os.Open(filepath.Join(keysDir, "private.asc"))
		if err != nil {
			log.Fatalf("[KEY LOAD] Error opening private key file: %v", err)
		}
		defer privFile.Close()
		keyRing, err := openpgp.ReadArmoredKeyRing(privFile)
		if err != nil {
			log.Fatalf("[KEY LOAD] Error reading armored key ring: %v", err)
		}
		if len(keyRing) == 0 {
			log.Fatal("[KEY LOAD] No keys found in private.asc")
		}
		myFingerprint = fmt.Sprintf("%X", keyRing[0].PrimaryKey.Fingerprint)
		log.Printf("[KEY LOAD] Loaded fingerprint from keys/private.asc: %s", myFingerprint)
		senderEntity = keyRing[0]
	}

	database = initDatabase()
	defer database.Close()

	go resetRateLimiter()

	// Start servers.
	srv := runRESTServer("8080")
	go runCommServer("6969")

	// Graceful shutdown on interrupt.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	log.Println("[SHUTDOWN] Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("[SHUTDOWN] Server Shutdown Failed: %+v", err)
	}
	log.Println("[SHUTDOWN] Server gracefully stopped.")
}

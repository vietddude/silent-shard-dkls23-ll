// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

package dkls

/*
#cgo LDFLAGS: -L${SRCDIR}/../target/release -Wl,-rpath,${SRCDIR}/../target/release -ldkls_go_ll -ldl -lm
// To use a custom library path, set CGO_LDFLAGS environment variable:
// export CGO_LDFLAGS="-L/path/to/lib -Wl,-rpath,/path/to/lib -ldkls_go_ll -ldl -lm"
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t* data;
    size_t len;
    size_t cap;
} ByteBuffer;

typedef struct {
    uint8_t from_id;
    uint8_t to_id;
    ByteBuffer payload;
} Message;

typedef struct {
    Message* msgs;
    size_t len;
} MessageArray;

typedef struct {
    char* message;
    int32_t code;
} GoError;

// Error handling
extern void dkls_free_error(GoError* err);
extern const char* dkls_error_message(const GoError* err);
extern int32_t dkls_error_code(const GoError* err);

// Byte buffer
extern void dkls_free_bytes(ByteBuffer buf);

// Keyshare
typedef void* KeyshareHandle;
extern KeyshareHandle dkls_keyshare_from_bytes(const uint8_t* bytes, size_t len);
extern ByteBuffer dkls_keyshare_to_bytes(const KeyshareHandle handle);
extern int dkls_keyshare_public_key(const KeyshareHandle handle, uint8_t* out);
extern uint8_t dkls_keyshare_participants(const KeyshareHandle handle);
extern uint8_t dkls_keyshare_threshold(const KeyshareHandle handle);
extern uint8_t dkls_keyshare_party_id(const KeyshareHandle handle);
extern void dkls_keyshare_free(KeyshareHandle handle);

// Message
extern void dkls_message_free(Message* msg);
extern void dkls_message_free_array(Message* msgs, size_t len);

// Keygen
typedef void* KeygenSessionHandle;
extern KeygenSessionHandle dkls_keygen_new(uint8_t participants, uint8_t threshold, uint8_t party_id, const uint8_t* seed, size_t seed_len);
extern ByteBuffer dkls_keygen_to_bytes(const KeygenSessionHandle handle);
extern KeygenSessionHandle dkls_keygen_from_bytes(const uint8_t* bytes, size_t len);
extern KeygenSessionHandle dkls_keygen_init_key_rotation(const KeyshareHandle oldshare, const uint8_t* seed, size_t seed_len, GoError** err_out);
extern KeygenSessionHandle dkls_keygen_init_key_recovery(const KeyshareHandle oldshare, const uint8_t* lost_shares, size_t lost_shares_len, const uint8_t* seed, size_t seed_len, GoError** err_out);
extern KeygenSessionHandle dkls_keygen_init_lost_share_recovery(uint8_t participants, uint8_t threshold, uint8_t party_id, const uint8_t* pk, size_t pk_len, const uint8_t* lost_shares, size_t lost_shares_len, const uint8_t* seed, size_t seed_len, GoError** err_out);
extern Message* dkls_keygen_create_first_message(KeygenSessionHandle handle, GoError** err_out);
extern int dkls_keygen_calculate_commitment_2(const KeygenSessionHandle handle, uint8_t* out);
// dkls_keygen_handle_messages is defined in dkls_wrapper.c
extern int dkls_keygen_handle_messages(KeygenSessionHandle handle, const Message* msgs, size_t msgs_len, const uint8_t* commitments, size_t commitments_len, const uint8_t* seed, size_t seed_len, GoError** err_out, MessageArray* out);
extern KeyshareHandle dkls_keygen_keyshare(KeygenSessionHandle handle, GoError** err_out);
extern void dkls_keygen_free(KeygenSessionHandle handle);

// Sign
typedef void* SignSessionHandle;
extern SignSessionHandle dkls_sign_new(const KeyshareHandle keyshare, const char* chain_path, const uint8_t* seed, size_t seed_len, GoError** err_out);
extern ByteBuffer dkls_sign_to_bytes(const SignSessionHandle handle);
extern SignSessionHandle dkls_sign_from_bytes(const uint8_t* bytes, size_t len);
extern Message* dkls_sign_create_first_message(SignSessionHandle handle, GoError** err_out);
// dkls_sign_handle_messages is defined in dkls_wrapper.c
extern int dkls_sign_handle_messages(SignSessionHandle handle, const Message* msgs, size_t msgs_len, const uint8_t* seed, size_t seed_len, GoError** err_out, MessageArray* out);
extern Message* dkls_sign_last_message(SignSessionHandle handle, const uint8_t* message_hash, size_t message_hash_len, GoError** err_out);
extern int dkls_sign_combine(SignSessionHandle handle, const Message* msgs, size_t msgs_len, uint8_t* r_out, uint8_t* s_out, GoError** err_out);
extern void dkls_sign_free(SignSessionHandle handle);

// Sign OT Variant
typedef void* SignSessionOTVariantHandle;
extern SignSessionOTVariantHandle dkls_sign_ot_variant_new(const KeyshareHandle keyshare, const char* chain_path, const uint8_t* seed, size_t seed_len, GoError** err_out);
extern ByteBuffer dkls_sign_ot_variant_to_bytes(const SignSessionOTVariantHandle handle);
extern SignSessionOTVariantHandle dkls_sign_ot_variant_from_bytes(const uint8_t* bytes, size_t len);
extern Message* dkls_sign_ot_variant_create_first_message(SignSessionOTVariantHandle handle, GoError** err_out);
// dkls_sign_ot_variant_handle_messages is defined in dkls_wrapper.c
extern int dkls_sign_ot_variant_handle_messages(SignSessionOTVariantHandle handle, const Message* msgs, size_t msgs_len, const uint8_t* seed, size_t seed_len, GoError** err_out, MessageArray* out);
extern Message* dkls_sign_ot_variant_last_message(SignSessionOTVariantHandle handle, const uint8_t* message_hash, size_t message_hash_len, GoError** err_out);
extern int dkls_sign_ot_variant_combine(SignSessionOTVariantHandle handle, const Message* msgs, size_t msgs_len, uint8_t* r_out, uint8_t* s_out, GoError** err_out);
extern void dkls_sign_ot_variant_free(SignSessionOTVariantHandle handle);
*/
import "C"

import (
	"errors"
	"unsafe"
)

// Error represents a DKLS error
type Error struct {
	Message string
	Code    int32
}

func (e *Error) Error() string {
	return e.Message
}

func getError(errPtr *C.GoError) *Error {
	if errPtr == nil {
		return nil
	}
	msg := C.dkls_error_message(errPtr)
	var msgStr string
	if msg != nil {
		msgStr = C.GoString(msg)
	}
	code := C.dkls_error_code(errPtr)
	return &Error{
		Message: msgStr,
		Code:    int32(code),
	}
}

func freeError(errPtr *C.GoError) {
	if errPtr != nil {
		C.dkls_free_error(errPtr)
	}
}

// ByteBuffer represents a byte buffer
type ByteBuffer struct {
	Data []byte
}

func freeByteBuffer(buf C.ByteBuffer) {
	if buf.data != nil {
		C.dkls_free_bytes(buf)
	}
}

func cByteBufferToGo(buf C.ByteBuffer) []byte {
	if buf.data == nil {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
}

// Message represents a protocol message
type Message struct {
	FromID  uint8
	ToID    *uint8 // nil means broadcast
	Payload []byte
}

func cMessageToGo(msg *C.Message) *Message {
	if msg == nil {
		return nil
	}
	var toID *uint8
	if msg.to_id != 255 {
		id := uint8(msg.to_id)
		toID = &id
	}
	return &Message{
		FromID:  uint8(msg.from_id),
		ToID:    toID,
		Payload: cByteBufferToGo(msg.payload),
	}
}

func goMessageToC(msg *Message) *C.Message {
	if msg == nil {
		return nil
	}
	toID := uint8(255)
	if msg.ToID != nil {
		toID = *msg.ToID
	}
	var payloadData unsafe.Pointer
	if len(msg.Payload) > 0 {
		payloadData = C.CBytes(msg.Payload)
	}
	return &C.Message{
		from_id: C.uint8_t(msg.FromID),
		to_id:   C.uint8_t(toID),
		payload: C.ByteBuffer{
			data: (*C.uint8_t)(payloadData),
			len:  C.size_t(len(msg.Payload)),
			cap:  C.size_t(len(msg.Payload)),
		},
	}
}

// goMessagesToC converts Go messages to C messages and returns both the C messages
// and a cleanup function that must be called to free the allocated memory.
func goMessagesToC(msgs []*Message) ([]C.Message, func()) {
	if len(msgs) == 0 {
		return nil, func() {}
	}
	cMsgs := make([]C.Message, len(msgs))
	// Track payload pointers to free them later
	// Use a map to deduplicate in case the same payload is used multiple times
	payloadPtrs := make(map[unsafe.Pointer]bool)
	
	for i, msg := range msgs {
		cMsg := goMessageToC(msg)
		cMsgs[i] = *cMsg
		// Track the payload pointer for cleanup
		// The payload was allocated with C.CBytes (malloc)
		if cMsg.payload.data != nil {
			payloadPtrs[unsafe.Pointer(cMsg.payload.data)] = true
		}
		// cMsg is allocated on Go heap, will be GC'd - don't free it
	}
	
	cleanup := func() {
		// Free all payload memory exactly once
		for ptr := range payloadPtrs {
			if ptr != nil {
				C.free(ptr)
			}
		}
	}
	return cMsgs, cleanup
}

// Keyshare represents a key share
type Keyshare struct {
	handle C.KeyshareHandle
}

// NewKeyshareFromBytes creates a keyshare from serialized bytes
func NewKeyshareFromBytes(data []byte) (*Keyshare, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	handle := C.dkls_keyshare_from_bytes((*C.uint8_t)(&data[0]), C.size_t(len(data)))
	if handle == nil {
		return nil, errors.New("failed to deserialize keyshare")
	}
	return &Keyshare{handle: handle}, nil
}

// ToBytes serializes the keyshare
func (k *Keyshare) ToBytes() ([]byte, error) {
	if k.handle == nil {
		return nil, errors.New("nil keyshare")
	}
	buf := C.dkls_keyshare_to_bytes(k.handle)
	defer freeByteBuffer(buf)
	return cByteBufferToGo(buf), nil
}

// PublicKey returns the public key (33 bytes)
func (k *Keyshare) PublicKey() ([]byte, error) {
	if k.handle == nil {
		return nil, errors.New("nil keyshare")
	}
	out := make([]byte, 33)
	if C.dkls_keyshare_public_key(k.handle, (*C.uint8_t)(&out[0])) != 0 {
		return nil, errors.New("failed to get public key")
	}
	return out, nil
}

// Participants returns the number of participants
func (k *Keyshare) Participants() uint8 {
	if k.handle == nil {
		return 0
	}
	return uint8(C.dkls_keyshare_participants(k.handle))
}

// Threshold returns the threshold
func (k *Keyshare) Threshold() uint8 {
	if k.handle == nil {
		return 0
	}
	return uint8(C.dkls_keyshare_threshold(k.handle))
}

// PartyID returns the party ID
func (k *Keyshare) PartyID() uint8 {
	if k.handle == nil {
		return 0
	}
	return uint8(C.dkls_keyshare_party_id(k.handle))
}

// Free releases the keyshare
func (k *Keyshare) Free() {
	if k.handle != nil {
		C.dkls_keyshare_free(k.handle)
		k.handle = nil
	}
}

// KeygenSession represents a key generation session
type KeygenSession struct {
	handle C.KeygenSessionHandle
}

// NewKeygenSession creates a new keygen session
func NewKeygenSession(participants, threshold, partyID uint8, seed []byte) *KeygenSession {
	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(&seed[0])
		seedLen = C.size_t(len(seed))
	}
	handle := C.dkls_keygen_new(C.uint8_t(participants), C.uint8_t(threshold), C.uint8_t(partyID), seedPtr, seedLen)
	return &KeygenSession{handle: handle}
}

// NewKeygenSessionFromBytes creates a keygen session from serialized bytes
func NewKeygenSessionFromBytes(data []byte) (*KeygenSession, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	handle := C.dkls_keygen_from_bytes((*C.uint8_t)(&data[0]), C.size_t(len(data)))
	if handle == nil {
		return nil, errors.New("failed to deserialize session")
	}
	return &KeygenSession{handle: handle}, nil
}

// ToBytes serializes the session
func (s *KeygenSession) ToBytes() ([]byte, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	buf := C.dkls_keygen_to_bytes(s.handle)
	defer freeByteBuffer(buf)
	return cByteBufferToGo(buf), nil
}

// InitKeyRotation initializes key rotation
func InitKeyRotation(oldShare *Keyshare, seed []byte) (*KeygenSession, error) {
	if oldShare == nil || oldShare.handle == nil {
		return nil, errors.New("nil keyshare")
	}
	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(&seed[0])
		seedLen = C.size_t(len(seed))
	}
	var errPtr *C.GoError
	handle := C.dkls_keygen_init_key_rotation(oldShare.handle, seedPtr, seedLen, &errPtr)
	if handle == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to init key rotation")
	}
	return &KeygenSession{handle: handle}, nil
}

// InitKeyRecovery initializes key recovery
func InitKeyRecovery(oldShare *Keyshare, lostShares []byte, seed []byte) (*KeygenSession, error) {
	if oldShare == nil || oldShare.handle == nil {
		return nil, errors.New("nil keyshare")
	}
	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(&seed[0])
		seedLen = C.size_t(len(seed))
	}
	var lostSharesPtr *C.uint8_t
	var lostSharesLen C.size_t
	if len(lostShares) > 0 {
		lostSharesPtr = (*C.uint8_t)(&lostShares[0])
		lostSharesLen = C.size_t(len(lostShares))
	}
	var errPtr *C.GoError
	handle := C.dkls_keygen_init_key_recovery(oldShare.handle, lostSharesPtr, lostSharesLen, seedPtr, seedLen, &errPtr)
	if handle == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to init key recovery")
	}
	return &KeygenSession{handle: handle}, nil
}

// InitLostShareRecovery initializes lost share recovery
func InitLostShareRecovery(participants, threshold, partyID uint8, pk []byte, lostShares []byte, seed []byte) (*KeygenSession, error) {
	if len(pk) != 33 {
		return nil, errors.New("invalid public key size")
	}
	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(&seed[0])
		seedLen = C.size_t(len(seed))
	}
	var lostSharesPtr *C.uint8_t
	var lostSharesLen C.size_t
	if len(lostShares) > 0 {
		lostSharesPtr = (*C.uint8_t)(&lostShares[0])
		lostSharesLen = C.size_t(len(lostShares))
	}
	var errPtr *C.GoError
	handle := C.dkls_keygen_init_lost_share_recovery(
		C.uint8_t(participants),
		C.uint8_t(threshold),
		C.uint8_t(partyID),
		(*C.uint8_t)(&pk[0]),
		C.size_t(len(pk)),
		lostSharesPtr,
		lostSharesLen,
		seedPtr,
		seedLen,
		&errPtr,
	)
	if handle == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to init lost share recovery")
	}
	return &KeygenSession{handle: handle}, nil
}

// CreateFirstMessage creates the first message
func (s *KeygenSession) CreateFirstMessage() (*Message, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	var errPtr *C.GoError
	msg := C.dkls_keygen_create_first_message(s.handle, &errPtr)
	if msg == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to create first message")
	}
	defer C.dkls_message_free(msg)
	return cMessageToGo(msg), nil
}

// CalculateCommitment2 calculates the commitment for round 2
func (s *KeygenSession) CalculateCommitment2() ([]byte, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	out := make([]byte, 32)
	if C.dkls_keygen_calculate_commitment_2(s.handle, (*C.uint8_t)(&out[0])) != 0 {
		return nil, errors.New("failed to calculate commitment")
	}
	return out, nil
}

// HandleMessages handles incoming messages
func (s *KeygenSession) HandleMessages(msgs []*Message, commitments []byte, seed []byte) ([]*Message, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	if len(msgs) == 0 {
		return nil, errors.New("empty messages")
	}

	// Convert Go messages to C
	cMsgs, cleanup := goMessagesToC(msgs)
	defer cleanup()

	var commitmentsPtr *C.uint8_t
	var commitmentsLen C.size_t
	if len(commitments) > 0 {
		commitmentsPtr = (*C.uint8_t)(&commitments[0])
		commitmentsLen = C.size_t(len(commitments))
	}

	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(&seed[0])
		seedLen = C.size_t(len(seed))
	}

	var errPtr *C.GoError
	var outArray C.MessageArray

	if len(cMsgs) > 0 {
		if C.dkls_keygen_handle_messages(
			s.handle,
			&cMsgs[0],
			C.size_t(len(cMsgs)),
			commitmentsPtr,
			commitmentsLen,
			seedPtr,
			seedLen,
			&errPtr,
			&outArray,
		) != 0 {
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("failed to handle messages")
		}
	} else {
		// Empty messages case
		if C.dkls_keygen_handle_messages(
			s.handle,
			(*C.Message)(nil),
			0,
			commitmentsPtr,
			commitmentsLen,
			seedPtr,
			seedLen,
			&errPtr,
			&outArray,
		) != 0 {
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("failed to handle messages")
		}
	}

	if outArray.len == 0 {
		return nil, nil
	}

	// Convert C messages to Go
	result := make([]*Message, outArray.len)
	if outArray.msgs != nil {
		cMsgSlice := (*[1 << 30]C.Message)(unsafe.Pointer(outArray.msgs))[:outArray.len:outArray.len]
		for i := uintptr(0); i < uintptr(outArray.len); i++ {
			result[i] = cMessageToGo(&cMsgSlice[i])
		}
		C.dkls_message_free_array(outArray.msgs, outArray.len)
	}

	return result, nil
}

// Keyshare extracts the keyshare from a completed session
func (s *KeygenSession) Keyshare() (*Keyshare, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	var errPtr *C.GoError
	handle := C.dkls_keygen_keyshare(s.handle, &errPtr)
	s.handle = nil // Session is consumed
	if handle == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to extract keyshare")
	}
	return &Keyshare{handle: handle}, nil
}

// Free releases the session
func (s *KeygenSession) Free() {
	if s.handle != nil {
		C.dkls_keygen_free(s.handle)
		s.handle = nil
	}
}

// SignSession represents a signing session
type SignSession struct {
	handle C.SignSessionHandle
}

// NewSignSession creates a new sign session
func NewSignSession(keyshare *Keyshare, chainPath string, seed []byte) (*SignSession, error) {
	if keyshare == nil || keyshare.handle == nil {
		return nil, errors.New("nil keyshare")
	}
	cPath := C.CString(chainPath)
	defer C.free(unsafe.Pointer(cPath))

	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(&seed[0])
		seedLen = C.size_t(len(seed))
	}

	var errPtr *C.GoError
	handle := C.dkls_sign_new(keyshare.handle, cPath, seedPtr, seedLen, &errPtr)
	if handle == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to create sign session")
	}
	return &SignSession{handle: handle}, nil
}

// NewSignSessionFromBytes creates a sign session from serialized bytes
func NewSignSessionFromBytes(data []byte) (*SignSession, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	handle := C.dkls_sign_from_bytes((*C.uint8_t)(&data[0]), C.size_t(len(data)))
	if handle == nil {
		return nil, errors.New("failed to deserialize session")
	}
	return &SignSession{handle: handle}, nil
}

// ToBytes serializes the session
func (s *SignSession) ToBytes() ([]byte, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	buf := C.dkls_sign_to_bytes(s.handle)
	defer freeByteBuffer(buf)
	return cByteBufferToGo(buf), nil
}

// CreateFirstMessage creates the first message
func (s *SignSession) CreateFirstMessage() (*Message, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	var errPtr *C.GoError
	msg := C.dkls_sign_create_first_message(s.handle, &errPtr)
	if msg == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to create first message")
	}
	defer C.dkls_message_free(msg)
	return cMessageToGo(msg), nil
}

// HandleMessages handles incoming messages
func (s *SignSession) HandleMessages(msgs []*Message, seed []byte) ([]*Message, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	if len(msgs) == 0 {
		return nil, errors.New("empty messages")
	}

	// Convert Go messages to C
	cMsgs, cleanup := goMessagesToC(msgs)
	defer cleanup()

	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(&seed[0])
		seedLen = C.size_t(len(seed))
	}

	var errPtr *C.GoError
	var outArray C.MessageArray

	if len(cMsgs) > 0 {
		if C.dkls_sign_handle_messages(
			s.handle,
			&cMsgs[0],
			C.size_t(len(cMsgs)),
			seedPtr,
			seedLen,
			&errPtr,
			&outArray,
		) != 0 {
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("failed to handle messages")
		}
	} else {
		// Empty messages case
		if C.dkls_sign_handle_messages(
			s.handle,
			(*C.Message)(nil),
			0,
			seedPtr,
			seedLen,
			&errPtr,
			&outArray,
		) != 0 {
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("failed to handle messages")
		}
	}

	if outArray.len == 0 {
		return nil, nil
	}

	// Convert C messages to Go
	result := make([]*Message, outArray.len)
	if outArray.msgs != nil {
		cMsgSlice := (*[1 << 30]C.Message)(unsafe.Pointer(outArray.msgs))[:outArray.len:outArray.len]
		for i := uintptr(0); i < uintptr(outArray.len); i++ {
			result[i] = cMessageToGo(&cMsgSlice[i])
		}
		C.dkls_message_free_array(outArray.msgs, outArray.len)
	}

	return result, nil
}

// LastMessage creates the last message with the message hash
func (s *SignSession) LastMessage(messageHash []byte) (*Message, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	if len(messageHash) != 32 {
		return nil, errors.New("message hash must be 32 bytes")
	}
	var errPtr *C.GoError
	msg := C.dkls_sign_last_message(s.handle, (*C.uint8_t)(&messageHash[0]), C.size_t(len(messageHash)), &errPtr)
	if msg == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to create last message")
	}
	defer C.dkls_message_free(msg)
	return cMessageToGo(msg), nil
}

// Combine combines partial signatures and returns the final signature
func (s *SignSession) Combine(msgs []*Message) (r, s_out []byte, err error) {
	if s.handle == nil {
		return nil, nil, errors.New("nil session")
	}
	if len(msgs) == 0 {
		return nil, nil, errors.New("empty messages")
	}

	// Convert Go messages to C
	cMsgs, cleanup := goMessagesToC(msgs)
	defer cleanup()

	rOut := make([]byte, 32)
	sOut := make([]byte, 32)

	var errPtr *C.GoError
	if len(cMsgs) > 0 {
		if C.dkls_sign_combine(
			s.handle,
			&cMsgs[0],
			C.size_t(len(cMsgs)),
			(*C.uint8_t)(&rOut[0]),
			(*C.uint8_t)(&sOut[0]),
			&errPtr,
		) != 0 {
			s.handle = nil // Session is consumed
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, nil, err
			}
			return nil, nil, errors.New("failed to combine signatures")
		}
	} else {
		// Empty messages case
		if C.dkls_sign_combine(
			s.handle,
			(*C.Message)(nil),
			0,
			(*C.uint8_t)(&rOut[0]),
			(*C.uint8_t)(&sOut[0]),
			&errPtr,
		) != 0 {
			s.handle = nil // Session is consumed
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, nil, err
			}
			return nil, nil, errors.New("failed to combine signatures")
		}
	}

	s.handle = nil // Session is consumed
	return rOut, sOut, nil
}

// Free releases the session
func (s *SignSession) Free() {
	if s.handle != nil {
		C.dkls_sign_free(s.handle)
		s.handle = nil
	}
}

// SignSessionOTVariant represents an OT variant signing session
type SignSessionOTVariant struct {
	handle C.SignSessionOTVariantHandle
}

// NewSignSessionOTVariant creates a new OT variant sign session
func NewSignSessionOTVariant(keyshare *Keyshare, chainPath string, seed []byte) (*SignSessionOTVariant, error) {
	if keyshare == nil || keyshare.handle == nil {
		return nil, errors.New("nil keyshare")
	}
	cPath := C.CString(chainPath)
	defer C.free(unsafe.Pointer(cPath))

	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(&seed[0])
		seedLen = C.size_t(len(seed))
	}

	var errPtr *C.GoError
	handle := C.dkls_sign_ot_variant_new(keyshare.handle, cPath, seedPtr, seedLen, &errPtr)
	if handle == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to create sign session")
	}
	return &SignSessionOTVariant{handle: handle}, nil
}

// NewSignSessionOTVariantFromBytes creates an OT variant sign session from serialized bytes
func NewSignSessionOTVariantFromBytes(data []byte) (*SignSessionOTVariant, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	handle := C.dkls_sign_ot_variant_from_bytes((*C.uint8_t)(&data[0]), C.size_t(len(data)))
	if handle == nil {
		return nil, errors.New("failed to deserialize session")
	}
	return &SignSessionOTVariant{handle: handle}, nil
}

// ToBytes serializes the session
func (s *SignSessionOTVariant) ToBytes() ([]byte, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	buf := C.dkls_sign_ot_variant_to_bytes(s.handle)
	defer freeByteBuffer(buf)
	return cByteBufferToGo(buf), nil
}

// CreateFirstMessage creates the first message
func (s *SignSessionOTVariant) CreateFirstMessage() (*Message, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	var errPtr *C.GoError
	msg := C.dkls_sign_ot_variant_create_first_message(s.handle, &errPtr)
	if msg == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to create first message")
	}
	defer C.dkls_message_free(msg)
	return cMessageToGo(msg), nil
}

// HandleMessages handles incoming messages
func (s *SignSessionOTVariant) HandleMessages(msgs []*Message, seed []byte) ([]*Message, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	if len(msgs) == 0 {
		return nil, errors.New("empty messages")
	}

	// Convert Go messages to C
	cMsgs, cleanup := goMessagesToC(msgs)
	defer cleanup()

	var seedPtr *C.uint8_t
	var seedLen C.size_t
	if len(seed) > 0 {
		seedPtr = (*C.uint8_t)(&seed[0])
		seedLen = C.size_t(len(seed))
	}

	var errPtr *C.GoError
	var outArray C.MessageArray

	if len(cMsgs) > 0 {
		if C.dkls_sign_ot_variant_handle_messages(
			s.handle,
			&cMsgs[0],
			C.size_t(len(cMsgs)),
			seedPtr,
			seedLen,
			&errPtr,
			&outArray,
		) != 0 {
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("failed to handle messages")
		}
	} else {
		// Empty messages case
		if C.dkls_sign_ot_variant_handle_messages(
			s.handle,
			(*C.Message)(nil),
			0,
			seedPtr,
			seedLen,
			&errPtr,
			&outArray,
		) != 0 {
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("failed to handle messages")
		}
	}

	if outArray.len == 0 {
		return nil, nil
	}

	// Convert C messages to Go
	result := make([]*Message, outArray.len)
	if outArray.msgs != nil {
		cMsgSlice := (*[1 << 30]C.Message)(unsafe.Pointer(outArray.msgs))[:outArray.len:outArray.len]
		for i := uintptr(0); i < uintptr(outArray.len); i++ {
			result[i] = cMessageToGo(&cMsgSlice[i])
		}
		C.dkls_message_free_array(outArray.msgs, outArray.len)
	}

	return result, nil
}

// LastMessage creates the last message with the message hash
func (s *SignSessionOTVariant) LastMessage(messageHash []byte) (*Message, error) {
	if s.handle == nil {
		return nil, errors.New("nil session")
	}
	if len(messageHash) != 32 {
		return nil, errors.New("message hash must be 32 bytes")
	}
	var errPtr *C.GoError
	msg := C.dkls_sign_ot_variant_last_message(s.handle, (*C.uint8_t)(&messageHash[0]), C.size_t(len(messageHash)), &errPtr)
	if msg == nil {
		err := getError(errPtr)
		freeError(errPtr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to create last message")
	}
	defer C.dkls_message_free(msg)
	return cMessageToGo(msg), nil
}

// Combine combines partial signatures and returns the final signature
func (s *SignSessionOTVariant) Combine(msgs []*Message) (r, s_out []byte, err error) {
	if s.handle == nil {
		return nil, nil, errors.New("nil session")
	}
	if len(msgs) == 0 {
		return nil, nil, errors.New("empty messages")
	}

	// Convert Go messages to C
	cMsgs, cleanup := goMessagesToC(msgs)
	defer cleanup()

	rOut := make([]byte, 32)
	sOut := make([]byte, 32)

	var errPtr *C.GoError
	if len(cMsgs) > 0 {
		if C.dkls_sign_ot_variant_combine(
			s.handle,
			&cMsgs[0],
			C.size_t(len(cMsgs)),
			(*C.uint8_t)(&rOut[0]),
			(*C.uint8_t)(&sOut[0]),
			&errPtr,
		) != 0 {
			s.handle = nil // Session is consumed
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, nil, err
			}
			return nil, nil, errors.New("failed to combine signatures")
		}
	} else {
		// Empty messages case
		if C.dkls_sign_ot_variant_combine(
			s.handle,
			(*C.Message)(nil),
			0,
			(*C.uint8_t)(&rOut[0]),
			(*C.uint8_t)(&sOut[0]),
			&errPtr,
		) != 0 {
			s.handle = nil // Session is consumed
			err := getError(errPtr)
			freeError(errPtr)
			if err != nil {
				return nil, nil, err
			}
			return nil, nil, errors.New("failed to combine signatures")
		}
	}

	s.handle = nil // Session is consumed
	return rOut, sOut, nil
}

// Free releases the session
func (s *SignSessionOTVariant) Free() {
	if s.handle != nil {
		C.dkls_sign_ot_variant_free(s.handle)
		s.handle = nil
	}
}

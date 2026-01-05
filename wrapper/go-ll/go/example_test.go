// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

package dkls

import (
	"fmt"
	"log"
)

// Example demonstrates a basic 2-of-2 key generation and signing flow
func Example_basicFlow() {
	// Step 1: Create keygen sessions for 2 participants
	party0 := NewKeygenSession(2, 2, 0, nil)
	party1 := NewKeygenSession(2, 2, 1, nil)
	defer party0.Free()
	defer party1.Free()

	// Step 2: Run key generation protocol
	// (In practice, this would be done over network between parties)
	msg1_0, _ := party0.CreateFirstMessage()
	msg1_1, _ := party1.CreateFirstMessage()

	msg2_0, _ := party0.HandleMessages([]*Message{msg1_1}, nil, nil)
	msg2_1, _ := party1.HandleMessages([]*Message{msg1_0}, nil, nil)

	commit0, _ := party0.CalculateCommitment2()
	commit1, _ := party1.CalculateCommitment2()
	commitments := append(commit0, commit1...)

	msg3_0, _ := party0.HandleMessages(selectMessagesForParty(msg2_0, 0), nil, nil)
	msg3_1, _ := party1.HandleMessages(selectMessagesForParty(msg2_1, 1), nil, nil)

	msg4_0, _ := party0.HandleMessages(selectMessagesForParty(msg3_0, 0), commitments, nil)
	msg4_1, _ := party1.HandleMessages(selectMessagesForParty(msg3_1, 1), commitments, nil)

	party0.HandleMessages(msg4_1, nil, nil)
	party1.HandleMessages(msg4_0, nil, nil)

	// Step 3: Extract keyshares
	share0, _ := party0.Keyshare()
	share1, _ := party1.Keyshare()
	defer share0.Free()
	defer share1.Free()

	// Step 4: Get public key
	pk, _ := share0.PublicKey()
	fmt.Printf("Generated public key: %x\n", pk)

	// Step 5: Create sign sessions
	sign0, _ := NewSignSession(share0, "m", nil)
	sign1, _ := NewSignSession(share1, "m", nil)
	defer sign0.Free()
	defer sign1.Free()

	// Step 6: Sign a message
	messageHash := make([]byte, 32)
	for i := range messageHash {
		messageHash[i] = byte(i)
	}

	// Run signing protocol (simplified - see tests for full example)
	msg1_0, _ = sign0.CreateFirstMessage()
	msg1_1, _ = sign1.CreateFirstMessage()

	msg2_0, _ = sign0.HandleMessages([]*Message{msg1_1}, nil)
	msg2_1, _ = sign1.HandleMessages([]*Message{msg1_0}, nil)

	msg3_0, _ = sign0.HandleMessages(selectMessagesForParty(msg2_0, 0), nil)
	msg3_1, _ = sign1.HandleMessages(selectMessagesForParty(msg2_1, 1), nil)

	sign0.HandleMessages(selectMessagesForParty(msg3_0, 0), nil)
	sign1.HandleMessages(selectMessagesForParty(msg3_1, 1), nil)

	last0, _ := sign0.LastMessage(messageHash)
	last1, _ := sign1.LastMessage(messageHash)
	_ = last0 // Use last0 to avoid unused variable warning

	r, s, _ := sign0.Combine([]*Message{last1})
	fmt.Printf("Signature r: %x\n", r)
	fmt.Printf("Signature s: %x\n", s)
}

func selectMessagesForParty(msgs []*Message, partyID uint8) []*Message {
	result := make([]*Message, 0)
	for _, msg := range msgs {
		if msg.ToID != nil && *msg.ToID == partyID {
			result = append(result, msg)
		}
	}
	return result
}

// ExampleKeyshareSerialization demonstrates how to serialize and deserialize keyshares
func Example_keyshareSerialization() {
	// Create a keyshare (in practice, this would come from DKG)
	// For this example, we'll simulate by creating a session and extracting a share
	party := NewKeygenSession(2, 2, 0, nil)
	defer party.Free()

	// ... run DKG protocol ...
	share, _ := party.Keyshare()
	defer share.Free()

	// Serialize the keyshare
	data, err := share.ToBytes()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Serialized keyshare size: %d bytes\n", len(data))

	// Deserialize the keyshare
	share2, err := NewKeyshareFromBytes(data)
	if err != nil {
		log.Fatal(err)
	}
	defer share2.Free()

	// Verify they match
	pk1, _ := share.PublicKey()
	pk2, _ := share2.PublicKey()
	if fmt.Sprintf("%x", pk1) == fmt.Sprintf("%x", pk2) {
		fmt.Println("Keyshares match after serialization")
	}
	_ = pk1
	_ = pk2
}

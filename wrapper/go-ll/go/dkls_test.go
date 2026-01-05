// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

package dkls

import (
	"bytes"
	"testing"
)

// Helper functions

func filterMessages(msgs []*Message, partyID uint8) []*Message {
	result := make([]*Message, 0)
	for _, msg := range msgs {
		if msg.FromID != partyID {
			result = append(result, msg)
		}
	}
	return result
}

func selectMessages(msgs []*Message, partyID uint8) []*Message {
	result := make([]*Message, 0)
	for _, msg := range msgs {
		if msg.ToID != nil && *msg.ToID == partyID {
			result = append(result, msg)
		}
	}
	return result
}

func runDKG(n, t uint8) ([]*Keyshare, error) {
	parties := make([]*KeygenSession, n)
	for i := uint8(0); i < n; i++ {
		parties[i] = NewKeygenSession(n, t, i, nil)
	}

	// Round 1: Create first messages
	msg1 := make([]*Message, n)
	for i, party := range parties {
		var err error
		msg1[i], err = party.CreateFirstMessage()
		if err != nil {
			return nil, err
		}
	}

	// Round 2: Handle first messages
	msg2 := make([]*Message, 0)
	for i, party := range parties {
		batch := filterMessages(msg1, uint8(i))
		out, err := party.HandleMessages(batch, nil, nil)
		if err != nil {
			return nil, err
		}
		msg2 = append(msg2, out...)
	}

	// Calculate commitments
	commitments := make([]byte, n*32)
	for i, party := range parties {
		commitment, err := party.CalculateCommitment2()
		if err != nil {
			return nil, err
		}
		copy(commitments[i*32:], commitment)
	}

	// Round 3: Handle second messages
	msg3 := make([]*Message, 0)
	for i, party := range parties {
		batch := selectMessages(msg2, uint8(i))
		out, err := party.HandleMessages(batch, nil, nil)
		if err != nil {
			return nil, err
		}
		msg3 = append(msg3, out...)
	}

	// Round 4: Handle third messages with commitments
	msg4 := make([]*Message, 0)
	for i, party := range parties {
		batch := selectMessages(msg3, uint8(i))
		out, err := party.HandleMessages(batch, commitments, nil)
		if err != nil {
			return nil, err
		}
		msg4 = append(msg4, out...)
	}

	// Round 5: Handle fourth messages
	for i, party := range parties {
		batch := filterMessages(msg4, uint8(i))
		_, err := party.HandleMessages(batch, nil, nil)
		if err != nil {
			return nil, err
		}
	}

	// Extract keyshares
	shares := make([]*Keyshare, n)
	for i, party := range parties {
		var err error
		shares[i], err = party.Keyshare()
		if err != nil {
			return nil, err
		}
	}

	return shares, nil
}

func runDSG(shares []*Keyshare, t int, messageHash []byte) ([][]byte, error) {
	if len(messageHash) != 32 {
		messageHash = make([]byte, 32)
	}

	parties := make([]*SignSession, t)
	for i := 0; i < t; i++ {
		var err error
		parties[i], err = NewSignSession(shares[i], "m", nil)
		if err != nil {
			return nil, err
		}
		defer parties[i].Free()
	}

	// Round 1: Create first messages
	msg1 := make([]*Message, t)
	for i, party := range parties {
		var err error
		msg1[i], err = party.CreateFirstMessage()
		if err != nil {
			return nil, err
		}
	}

	// Round 2: Handle first messages
	msg2 := make([]*Message, 0)
	for i, party := range parties {
		batch := filterMessages(msg1, uint8(i))
		out, err := party.HandleMessages(batch, nil)
		if err != nil {
			return nil, err
		}
		msg2 = append(msg2, out...)
	}

	// Round 3: Handle second messages
	msg3 := make([]*Message, 0)
	for i, party := range parties {
		batch := selectMessages(msg2, uint8(i))
		out, err := party.HandleMessages(batch, nil)
		if err != nil {
			return nil, err
		}
		msg3 = append(msg3, out...)
	}

	// Round 4: Handle third messages
	for i, party := range parties {
		batch := selectMessages(msg3, uint8(i))
		_, err := party.HandleMessages(batch, nil)
		if err != nil {
			return nil, err
		}
	}

	// Create last messages
	msg4 := make([]*Message, t)
	for i, party := range parties {
		var err error
		msg4[i], err = party.LastMessage(messageHash)
		if err != nil {
			return nil, err
		}
	}

	// Combine signatures
	signatures := make([][]byte, t)
	for i, party := range parties {
		batch := filterMessages(msg4, uint8(i))
		r, s, err := party.Combine(batch)
		if err != nil {
			return nil, err
		}
		signatures[i] = append(r, s...)
	}

	return signatures, nil
}

// Tests

func TestDKG_2x2(t *testing.T) {
	shares, err := runDKG(2, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	if len(shares) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(shares))
	}

	// Verify all shares have the same public key
	pk0, err := shares[0].PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	for i := 1; i < len(shares); i++ {
		pk, err := shares[i].PublicKey()
		if err != nil {
			t.Fatalf("failed to get public key: %v", err)
		}
		if !bytes.Equal(pk0, pk) {
			t.Errorf("public keys don't match: share 0 vs share %d", i)
		}
	}

	// Verify metadata
	for i, share := range shares {
		if share.Participants() != 2 {
			t.Errorf("share %d: expected 2 participants, got %d", i, share.Participants())
		}
		if share.Threshold() != 2 {
			t.Errorf("share %d: expected threshold 2, got %d", i, share.Threshold())
		}
		if share.PartyID() != uint8(i) {
			t.Errorf("share %d: expected party ID %d, got %d", i, i, share.PartyID())
		}
	}
}

func TestDKG_3x2(t *testing.T) {
	shares, err := runDKG(3, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}

	// Verify all shares have the same public key
	pk0, err := shares[0].PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	for i := 1; i < len(shares); i++ {
		pk, err := shares[i].PublicKey()
		if err != nil {
			t.Fatalf("failed to get public key: %v", err)
		}
		if !bytes.Equal(pk0, pk) {
			t.Errorf("public keys don't match: share 0 vs share %d", i)
		}
	}
}

func TestDKG_3x3(t *testing.T) {
	shares, err := runDKG(3, 3)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}
}

func TestDKG_4x3(t *testing.T) {
	shares, err := runDKG(4, 3)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	if len(shares) != 4 {
		t.Fatalf("expected 4 shares, got %d", len(shares))
	}
}

func TestDSG_2x2(t *testing.T) {
	shares, err := runDKG(2, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	messageHash := make([]byte, 32)
	for i := range messageHash {
		messageHash[i] = 0xFF
	}

	signatures, err := runDSG(shares, 2, messageHash)
	if err != nil {
		t.Fatalf("DSG failed: %v", err)
	}

	if len(signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(signatures))
	}

	// Verify all signatures are identical
	sig0 := signatures[0]
	for i := 1; i < len(signatures); i++ {
		if !bytes.Equal(sig0, signatures[i]) {
			t.Errorf("signatures don't match: signature 0 vs signature %d", i)
		}
	}

	// Verify signature format (r and s are 32 bytes each)
	if len(sig0) != 64 {
		t.Errorf("expected signature length 64, got %d", len(sig0))
	}
}

func TestDSG_3x2(t *testing.T) {
	shares, err := runDKG(3, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	messageHash := make([]byte, 32)
	signatures, err := runDSG(shares, 2, messageHash)
	if err != nil {
		t.Fatalf("DSG failed: %v", err)
	}

	if len(signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(signatures))
	}

	// Verify all signatures are identical
	sig0 := signatures[0]
	for i := 1; i < len(signatures); i++ {
		if !bytes.Equal(sig0, signatures[i]) {
			t.Errorf("signatures don't match: signature 0 vs signature %d", i)
		}
	}
}

func TestDSG_3x3(t *testing.T) {
	shares, err := runDKG(3, 3)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	messageHash := make([]byte, 32)
	signatures, err := runDSG(shares, 3, messageHash)
	if err != nil {
		t.Fatalf("DSG failed: %v", err)
	}

	if len(signatures) != 3 {
		t.Fatalf("expected 3 signatures, got %d", len(signatures))
	}
}

func TestDSG_4x3(t *testing.T) {
	shares, err := runDKG(4, 3)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	messageHash := make([]byte, 32)
	signatures, err := runDSG(shares, 3, messageHash)
	if err != nil {
		t.Fatalf("DSG failed: %v", err)
	}

	if len(signatures) != 3 {
		t.Fatalf("expected 3 signatures, got %d", len(signatures))
	}
}

func TestKeyshareSerialization(t *testing.T) {
	shares, err := runDKG(2, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	// Test serialization
	share := shares[0]
	data, err := share.ToBytes()
	if err != nil {
		t.Fatalf("failed to serialize keyshare: %v", err)
	}

	// Test deserialization
	share2, err := NewKeyshareFromBytes(data)
	if err != nil {
		t.Fatalf("failed to deserialize keyshare: %v", err)
	}
	defer share2.Free()

	// Verify properties match
	if share.Participants() != share2.Participants() {
		t.Errorf("participants don't match: %d vs %d", share.Participants(), share2.Participants())
	}
	if share.Threshold() != share2.Threshold() {
		t.Errorf("thresholds don't match: %d vs %d", share.Threshold(), share2.Threshold())
	}
	if share.PartyID() != share2.PartyID() {
		t.Errorf("party IDs don't match: %d vs %d", share.PartyID(), share2.PartyID())
	}

	pk1, err := share.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}
	pk2, err := share2.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}
	if !bytes.Equal(pk1, pk2) {
		t.Errorf("public keys don't match")
	}
}

func TestKeyRotation(t *testing.T) {
	// Create initial shares
	oldShares, err := runDKG(3, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range oldShares {
			share.Free()
		}
	}()

	// Sign with old shares (create copies first since shares are consumed)
	oldShareCopies := make([]*Keyshare, len(oldShares))
	for i, share := range oldShares {
		data, err := share.ToBytes()
		if err != nil {
			t.Fatalf("failed to serialize: %v", err)
		}
		oldShareCopies[i], err = NewKeyshareFromBytes(data)
		if err != nil {
			t.Fatalf("failed to deserialize: %v", err)
		}
	}
	defer func() {
		for _, share := range oldShareCopies {
			share.Free()
		}
	}()

	messageHash := make([]byte, 32)
	_, err = runDSG(oldShareCopies, 2, messageHash)
	if err != nil {
		t.Fatalf("DSG failed: %v", err)
	}

	// Create more copies for rotation
	rotationShareCopies := make([]*Keyshare, len(oldShares))
	for i, share := range oldShares {
		data, err := share.ToBytes()
		if err != nil {
			t.Fatalf("failed to serialize: %v", err)
		}
		rotationShareCopies[i], err = NewKeyshareFromBytes(data)
		if err != nil {
			t.Fatalf("failed to deserialize: %v", err)
		}
	}
	defer func() {
		for _, share := range rotationShareCopies {
			share.Free()
		}
	}()

	// Init key rotation
	rotationParties := make([]*KeygenSession, len(oldShares))
	for i, share := range rotationShareCopies {
		var err error
		rotationParties[i], err = InitKeyRotation(share, nil)
		if err != nil {
			t.Fatalf("failed to init key rotation: %v", err)
		}
		defer rotationParties[i].Free()
	}

	// Run DKG protocol for rotation (simplified - in practice you'd run the full protocol)
	// For this test, we'll just verify the rotation sessions were created
	if len(rotationParties) != 3 {
		t.Errorf("expected 3 rotation parties, got %d", len(rotationParties))
	}
}

func TestKeyRecovery(t *testing.T) {
	// Create initial shares
	shares, err := runDKG(3, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	lostShares := []byte{0} // Party 0 lost their share
	pk, err := shares[0].PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	// Create recovery parties
	recoveryParties := make([]*KeygenSession, 3)

	// Party 0: lost share recovery
	recoveryParties[0], err = InitLostShareRecovery(3, 2, 0, pk, lostShares, nil)
	if err != nil {
		t.Fatalf("failed to init lost share recovery: %v", err)
	}
	defer recoveryParties[0].Free()

	// Parties 1 and 2: key recovery
	for i := 1; i < 3; i++ {
		shareData, err := shares[i].ToBytes()
		if err != nil {
			t.Fatalf("failed to serialize share: %v", err)
		}
		shareCopy, err := NewKeyshareFromBytes(shareData)
		if err != nil {
			t.Fatalf("failed to deserialize share: %v", err)
		}
		recoveryParties[i], err = InitKeyRecovery(shareCopy, lostShares, nil)
		if err != nil {
			t.Fatalf("failed to init key recovery: %v", err)
		}
		defer recoveryParties[i].Free()
		shareCopy.Free()
	}

	// Verify recovery parties were created successfully
	if len(recoveryParties) != 3 {
		t.Errorf("expected 3 recovery parties, got %d", len(recoveryParties))
	}

	// In a full test, you would run the DKG protocol with these recovery parties
	// and verify the new public key matches the old one
}

func TestKeygenSessionErrorHandling(t *testing.T) {
	session := NewKeygenSession(3, 2, 0, nil)
	defer session.Free()

	// Create first message
	msg1, err := session.CreateFirstMessage()
	if err != nil {
		t.Fatalf("failed to create first message: %v", err)
	}

	// Try to create first message again (should fail)
	_, err = session.CreateFirstMessage()
	if err == nil {
		t.Error("expected error when creating first message twice")
	}

	// Try to handle own message (should fail)
	_, err = session.HandleMessages([]*Message{msg1}, nil, nil)
	if err == nil {
		t.Error("expected error when handling own message")
	}
}

func TestSignSessionErrorHandling(t *testing.T) {
	shares, err := runDKG(2, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	session, err := NewSignSession(shares[0], "m", nil)
	if err != nil {
		t.Fatalf("failed to create sign session: %v", err)
	}
	defer session.Free()

	// Create first message
	msg1, err := session.CreateFirstMessage()
	if err != nil {
		t.Fatalf("failed to create first message: %v", err)
	}

	// Try to create first message again (should fail)
	_, err = session.CreateFirstMessage()
	if err == nil {
		t.Error("expected error when creating first message twice")
	}

	// Try to handle own message (should fail)
	_, err = session.HandleMessages([]*Message{msg1}, nil)
	if err == nil {
		t.Error("expected error when handling own message")
	}

	// Try to combine with invalid message hash
	invalidHash := make([]byte, 31) // Wrong size
	_, err = session.LastMessage(invalidHash)
	if err == nil {
		t.Error("expected error with invalid message hash size")
	}
}

func TestPublicKeyFormat(t *testing.T) {
	shares, err := runDKG(2, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	pk, err := shares[0].PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	// Public key should be 33 bytes (compressed secp256k1)
	if len(pk) != 33 {
		t.Errorf("expected public key length 33, got %d", len(pk))
	}
}

func TestMessageRouting(t *testing.T) {
	shares, err := runDKG(3, 2)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	defer func() {
		for _, share := range shares {
			share.Free()
		}
	}()

	session, err := NewSignSession(shares[0], "m", nil)
	if err != nil {
		t.Fatalf("failed to create sign session: %v", err)
	}
	defer session.Free()

	msg, err := session.CreateFirstMessage()
	if err != nil {
		t.Fatalf("failed to create message: %v", err)
	}

	// First message should be broadcast (ToID == nil)
	if msg.ToID != nil {
		t.Errorf("expected broadcast message, got ToID: %d", *msg.ToID)
	}

	// FromID should match party ID
	if msg.FromID != 0 {
		t.Errorf("expected FromID 0, got %d", msg.FromID)
	}
}

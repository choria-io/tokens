/*
 * Copyright (c) 2023-2023, R.I. Pienaar and the Choria Project contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package tokens

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

func ed25519Sign(pk ed25519.PrivateKey, msg []byte) ([]byte, error) {
	if len(pk) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	return ed25519.Sign(pk, msg), nil
}

func ed25519Verify(pk ed25519.PublicKey, msg []byte, sig []byte) (bool, error) {
	if len(pk) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size")
	}

	return ed25519.Verify(pk, msg, sig), nil
}

func ed25519SignWithSeedFile(f string, msg []byte) ([]byte, error) {
	_, pri, err := ed25519KeyPairFromSeedFile(f)
	if err != nil {
		return nil, err
	}

	return ed25519Sign(pri, msg)
}

func ed25519KeyPairFromSeedFile(f string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	ss, err := os.ReadFile(f)
	if err != nil {
		return nil, nil, err
	}

	seed, err := hex.DecodeString(string(ss))
	if err != nil {
		return nil, nil, err
	}

	return ed25519KeyPairFromSeed(seed)
}

func ed25519KeyPairFromSeed(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("invalid seed length")
	}

	priK := ed25519.NewKeyFromSeed(seed)
	pubK := priK.Public().(ed25519.PublicKey)
	return pubK, priK, nil
}

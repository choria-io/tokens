/*
 * Copyright (c) 2023-2023, R.I. Pienaar and the Choria Project contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package tokens

import (
	"encoding/hex"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Ed25519", func() {
	Describe("Signing", func() {
		It("Should make correct signatures", func() {
			td, err := os.MkdirTemp("", "")
			Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(td)

			seed, err := hex.DecodeString("8e306060341f7eb867c7d09609d53bfa9e6cb38ca744c0dca548572cc3080b6a")
			Expect(err).ToNot(HaveOccurred())
			pub, pri, err := ed25519KeyPairFromSeed(seed)
			Expect(err).ToNot(HaveOccurred())

			seedFile := filepath.Join(td, "key.seed")
			err = os.WriteFile(seedFile, []byte(hex.EncodeToString(seed)), 0600)
			Expect(err).ToNot(HaveOccurred())

			sig, err := ed25519Sign(pri, []byte("too many secrets"))
			Expect(err).ToNot(HaveOccurred())
			Expect(hex.EncodeToString(sig)).To(Equal("5971db5ce8eec72d586b0630e2cdd9464e6800b973e6c58575a4072018ca51a93f2e1988d47e058bb19c18d57a44ffa9931b6b7e2f70b5e44ddc50339a8c790b"))

			verify, err := ed25519Verify(pub, []byte("too many secrets"), sig)
			Expect(err).ToNot(HaveOccurred())
			Expect(verify).To(BeTrue())

			sig, err = ed25519SignWithSeedFile(seedFile, []byte("too many secrets"))
			Expect(err).ToNot(HaveOccurred())
			Expect(hex.EncodeToString(sig)).To(Equal("5971db5ce8eec72d586b0630e2cdd9464e6800b973e6c58575a4072018ca51a93f2e1988d47e058bb19c18d57a44ffa9931b6b7e2f70b5e44ddc50339a8c790b"))
		})
	})
})

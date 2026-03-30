// Copyright (c) 2021-2023, R.I. Pienaar and the Choria Project contributors
//
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func loadRSAPubKey(k string) *rsa.PublicKey {
	f, err := os.ReadFile(k)
	Expect(err).ToNot(HaveOccurred())
	pubK, err := jwt.ParseRSAPublicKeyFromPEM(f)
	Expect(err).ToNot(HaveOccurred())

	return pubK
}

func loadEd25519Seed(f string) (ed25519.PublicKey, ed25519.PrivateKey) {
	ss, err := os.ReadFile(f)
	Expect(err).ToNot(HaveOccurred())

	seed, err := hex.DecodeString(string(ss))
	Expect(err).ToNot(HaveOccurred())

	priK := ed25519.NewKeyFromSeed(seed)
	pubK := priK.Public().(ed25519.PublicKey)
	return pubK, priK
}

func loadRSAPriKey(k string) *rsa.PrivateKey {
	f, err := os.ReadFile(k)
	Expect(err).ToNot(HaveOccurred())
	pK, err := jwt.ParseRSAPrivateKeyFromPEM(f)
	Expect(err).ToNot(HaveOccurred())
	return pK
}

var _ = Describe("Tokens", func() {
	var (
		provJWTRSA     []byte
		provJWTED25519 []byte
		err            error
	)

	BeforeEach(func() {
		provJWTRSA, err = os.ReadFile("testdata/rsa/good-provisioning.jwt")
		Expect(err).ToNot(HaveOccurred())
		provJWTED25519, err = os.ReadFile("testdata/ed25519/good-provisioning.jwt")
		Expect(err).ToNot(HaveOccurred())

	})

	Describe("NatsConnectionHelpers", func() {
		var pk ed25519.PrivateKey
		var pubk ed25519.PublicKey
		var err error
		var log *logrus.Entry

		BeforeEach(func() {
			pubk, pk = loadEd25519Seed("testdata/ed25519/other.seed")
			Expect(err).ToNot(HaveOccurred())

			log = logrus.NewEntry(logrus.New())
			log.Logger.SetOutput(GinkgoWriter)
		})

		It("Should test required settings", func() {
			_, _, _, err := NatsConnectionHelpers("", "", "", log)
			Expect(err).To(MatchError("collective is required"))

			_, _, _, err = NatsConnectionHelpers("", "choria", "", log)
			Expect(err).To(MatchError("seedfile is required"))
		})

		It("Should fail for unsupported tokens", func() {
			pt, err := NewProvisioningClaims(true, true, "x", "", "", nil, "example.net", "", "", "choria", "", time.Hour)
			Expect(err).ToNot(HaveOccurred())

			token, err := SignToken(pt, pk)
			Expect(err).ToNot(HaveOccurred())

			_, _, _, err = NatsConnectionHelpers(token, "choria", "testdata/ed25519/other.seed", log)
			Expect(err).To(MatchError("unsupported token purpose: choria_provisioning"))
		})

		It("Should support client tokens", func() {
			ct, err := NewClientIDClaims("ginkgo", nil, "choria", nil, "", "", time.Hour, nil, pubk)
			Expect(err).ToNot(HaveOccurred())

			token, err := SignToken(ct, pk)
			Expect(err).ToNot(HaveOccurred())

			inbox, jh, sigh, err := NatsConnectionHelpers(token, "choria", "testdata/ed25519/other.seed", log)
			Expect(err).ToNot(HaveOccurred())
			Expect(inbox).To(Equal("choria.reply.4bb6777bb903cae3166e826932f7fe94"))
			Expect(jh()).To(Equal(token))

			expected, err := ed25519Sign(pk, []byte("toomanysecrets"))
			Expect(err).ToNot(HaveOccurred())
			Expect(sigh([]byte("toomanysecrets"))).To(Equal(expected))
		})

		It("Should support server tokens", func() {
			st, err := NewServerClaims("ginkgo.example.net", []string{"choria"}, "choria", nil, nil, pubk, "", time.Hour)
			Expect(err).ToNot(HaveOccurred())

			token, err := SignToken(st, pk)
			Expect(err).ToNot(HaveOccurred())

			inbox, jh, sigh, err := NatsConnectionHelpers(token, "choria", "testdata/ed25519/other.seed", log)
			Expect(err).ToNot(HaveOccurred())
			Expect(inbox).To(Equal("choria.reply.3f7c3a791b0eb10da51dca4cdedb9418"))
			Expect(jh()).To(Equal(token))

			expected, err := ed25519Sign(pk, []byte("toomanysecrets"))
			Expect(err).ToNot(HaveOccurred())
			Expect(sigh([]byte("toomanysecrets"))).To(Equal(expected))
		})
	})

	Describe("ParseTokenUnverified", func() {
		It("Should fail for invalid tokens", func() {
			_, err := ParseTokenUnverified("invalid")
			Expect(err).To(HaveOccurred())
		})

		It("Should parse valid tokens without verification", func() {
			claims, err := ParseTokenUnverified(string(provJWTRSA))
			Expect(err).ToNot(HaveOccurred())
			Expect(claims).ToNot(BeNil())
			Expect(claims["sub"]).To(Equal("choria_provisioning"))
		})

		It("Should parse expired tokens without error", func() {
			c, err := newStandardClaims("ginkgo", ClientIDPurpose, time.Hour, false)
			Expect(err).ToNot(HaveOccurred())
			c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
			signed, err := SignToken(c, loadRSAPriKey("testdata/rsa/signer-key.pem"))
			Expect(err).ToNot(HaveOccurred())

			claims, err := ParseTokenUnverified(signed)
			Expect(err).ToNot(HaveOccurred())
			Expect(claims).ToNot(BeNil())
			Expect(claims["purpose"]).To(Equal("choria_client_id"))
		})
	})

	Describe("TokenSigningAlgorithmBytes", func() {
		It("Should extract the correct algo from bytes", func() {
			alg, err := TokenSigningAlgorithmBytes(provJWTRSA)
			Expect(err).ToNot(HaveOccurred())
			Expect(alg).To(Equal("RS256"))

			alg, err = TokenSigningAlgorithmBytes(provJWTED25519)
			Expect(err).ToNot(HaveOccurred())
			Expect(alg).To(Equal("EdDSA"))
		})

		It("Should fail for invalid tokens", func() {
			_, err := TokenSigningAlgorithmBytes([]byte("invalid"))
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("ParseToken", func() {
		Describe("ED25519", func() {
			It("Should parse and verify the token", func() {
				claims := &jwt.MapClaims{}
				err = ParseToken(string(provJWTED25519), claims, nil)
				Expect(err).To(MatchError("invalid public key"))

				pubK, _ := loadEd25519Seed("testdata/ed25519/other.seed")
				err = ParseToken(string(provJWTED25519), claims, pubK)
				Expect(err).To(MatchError(ContainSubstring("ed25519: verification error")))

				err = ParseToken(string(provJWTED25519), claims, loadRSAPubKey("testdata/rsa/other-public.pem"))
				Expect(err).To(MatchError(ContainSubstring("ed25519 public key required")))

				pubK, _ = loadEd25519Seed("testdata/ed25519/signer.seed")
				err = ParseToken(string(provJWTED25519), claims, pubK)
				Expect(err).ToNot(HaveOccurred())

				sclaims, err := NewServerClaims("ginkgo.example.net", []string{"choria"}, "ginkgo_org", nil, nil, pubK, "ginkgo issuer", 365*24*time.Hour)
				Expect(err).ToNot(HaveOccurred())
				signed, err := SignTokenWithKeyFile(sclaims, "testdata/ed25519/signer.seed")
				Expect(err).ToNot(HaveOccurred())

				err = ParseToken(signed, claims, pubK)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Describe("RSA", func() {
			It("Should parse and verify the token", func() {
				claims := &jwt.MapClaims{}

				err = ParseToken(string(provJWTRSA), claims, nil)
				Expect(err).To(MatchError("invalid public key"))

				err = ParseToken(string(provJWTRSA), claims, loadRSAPubKey("testdata/rsa/other-public.pem"))
				Expect(err).To(MatchError(ContainSubstring("crypto/rsa: verification error")))

				pubK, _ := loadEd25519Seed("testdata/ed25519/other.seed")
				err = ParseToken(string(provJWTRSA), claims, pubK)
				Expect(err).To(MatchError(ContainSubstring("rsa public key required")))

				err = ParseToken(string(provJWTRSA), claims, loadRSAPubKey("testdata/rsa/signer-public.pem"))
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("TokenPurpose", func() {
		It("Should extract the correct purpose", func() {
			Expect(TokenPurposeBytes(provJWTRSA)).To(Equal(ProvisioningPurpose))
			Expect(TokenPurpose(string(provJWTRSA))).To(Equal(ProvisioningPurpose))
		})

		It("Should detect server purpose", func() {
			pubk, prik := loadEd25519Seed("testdata/ed25519/signer.seed")
			claims, err := NewServerClaims("ginkgo.example.net", []string{"choria"}, "ginkgo_org", nil, nil, pubk, "ginkgo", 365*24*time.Hour)
			Expect(err).ToNot(HaveOccurred())
			signed, err := SignToken(claims, prik)
			Expect(err).ToNot(HaveOccurred())
			Expect(TokenPurpose(signed)).To(Equal(ServerPurpose))
		})

		It("Should detect client id purpose", func() {
			pubk, prik := loadEd25519Seed("testdata/ed25519/signer.seed")
			claims, err := NewClientIDClaims("up=ginkgo", nil, "", nil, "", "", time.Hour, nil, pubk)
			Expect(err).ToNot(HaveOccurred())
			signed, err := SignToken(claims, prik)
			Expect(err).ToNot(HaveOccurred())
			Expect(TokenPurpose(signed)).To(Equal(ClientIDPurpose))
		})

		It("Should return unknown for invalid tokens", func() {
			Expect(TokenPurpose("invalid")).To(Equal(UnknownPurpose))
		})
	})

	Describe("TokenSigningAlgorithm", func() {
		It("Should extract the correct algo", func() {
			Expect(TokenSigningAlgorithm(string(provJWTRSA))).To(Equal("RS256"))
			Expect(TokenSigningAlgorithm(string(provJWTED25519))).To(Equal("EdDSA"))
		})
	})

	Describe("SignToken", func() {
		It("Should fail for unsupported key types", func() {
			claims, err := newStandardClaims("ginkgo", ProvisioningPurpose, 0, false)
			Expect(err).ToNot(HaveOccurred())
			_, err = SignToken(claims, "not a key")
			Expect(err).To(MatchError("unsupported private key"))
		})

		Describe("ED25519", func() {
			It("Should correctly sign the token", func() {
				claims, err := newStandardClaims("ginkgo", ProvisioningPurpose, 0, false)
				Expect(err).ToNot(HaveOccurred())

				pubK, priK := loadEd25519Seed("testdata/ed25519/signer.seed")

				t, err := SignToken(claims, priK)
				Expect(err).ToNot(HaveOccurred())

				claims = &StandardClaims{}
				err = ParseToken(t, claims, loadRSAPubKey("testdata/rsa/signer-public.pem"))
				Expect(err).To(MatchError(ContainSubstring("ed25519 public key required")))

				claims = &StandardClaims{}
				err = ParseToken(t, claims, pubK)
				Expect(err).ToNot(HaveOccurred())
				Expect(claims.Issuer).To(Equal("ginkgo"))
			})
		})

		Describe("RSA", func() {
			It("Should correctly sign the token", func() {
				claims, err := newStandardClaims("ginkgo", ProvisioningPurpose, 0, false)
				Expect(err).ToNot(HaveOccurred())
				t, err := SignToken(claims, loadRSAPriKey("testdata/rsa/signer-key.pem"))
				Expect(err).ToNot(HaveOccurred())

				pubK, _ := loadEd25519Seed("testdata/ed25519/signer.seed")

				claims = &StandardClaims{}
				err = ParseToken(t, claims, pubK)
				Expect(err).To(MatchError(ContainSubstring("rsa public key required")))

				err = ParseToken(t, claims, loadRSAPubKey("testdata/rsa/signer-public.pem"))
				Expect(err).ToNot(HaveOccurred())
				Expect(claims.Issuer).To(Equal("ginkgo"))
			})
		})
	})

	Describe("SignTokenWithKeyFile", func() {
		It("Should fail for missing key file", func() {
			claims, err := newStandardClaims("ginkgo", ProvisioningPurpose, 0, false)
			Expect(err).ToNot(HaveOccurred())
			_, err = SignTokenWithKeyFile(claims, "/nonexisting")
			Expect(err).To(MatchError(ContainSubstring("could not read signing key")))
		})

		It("Should fail for unsupported key file contents", func() {
			claims, err := newStandardClaims("ginkgo", ProvisioningPurpose, 0, false)
			Expect(err).ToNot(HaveOccurred())

			tf, err := os.CreateTemp("", "")
			Expect(err).ToNot(HaveOccurred())
			defer os.Remove(tf.Name())
			tf.WriteString("not a valid key")
			tf.Close()

			_, err = SignTokenWithKeyFile(claims, tf.Name())
			Expect(err).To(MatchError(ContainSubstring("unsupported key")))
		})

		Describe("ED25519", func() {
			It("Should correctly sign the token", func() {
				claims, err := newStandardClaims("ginkgo", ProvisioningPurpose, 0, false)
				Expect(err).ToNot(HaveOccurred())

				t, err := SignTokenWithKeyFile(claims, "testdata/ed25519/signer.seed")
				Expect(err).ToNot(HaveOccurred())

				pubK, _ := loadEd25519Seed("testdata/ed25519/signer.seed")
				claims = &StandardClaims{}
				err = ParseToken(t, claims, pubK)
				Expect(err).ToNot(HaveOccurred())
				Expect(claims.Issuer).To(Equal("ginkgo"))
			})
		})

		Describe("RSA", func() {
			It("Should correctly sign the token", func() {
				claims, err := newStandardClaims("ginkgo", ProvisioningPurpose, 0, false)
				Expect(err).ToNot(HaveOccurred())
				t, err := SignTokenWithKeyFile(claims, "testdata/rsa/signer-key.pem")
				Expect(err).ToNot(HaveOccurred())

				claims = &StandardClaims{}
				err = ParseToken(t, claims, loadRSAPubKey("testdata/rsa/signer-public.pem"))
				Expect(err).ToNot(HaveOccurred())
				Expect(claims.Issuer).To(Equal("ginkgo"))
			})
		})
	})

	Describe("SaveAndSignTokenWithKeyFile", func() {
		var td string
		var err error
		var claims *StandardClaims
		var out string

		BeforeEach(func() {
			td, err = os.MkdirTemp("", "")
			Expect(err).ToNot(HaveOccurred())
			out = filepath.Join(td, "token.jwt")
			claims, err = newStandardClaims("ginkgo", ProvisioningPurpose, 0, false)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			os.RemoveAll(td)
		})

		Describe("ED25519", func() {
			It("Should correctly sign and save", func() {
				err = SaveAndSignTokenWithKeyFile(claims, "testdata/ed25519/signer.seed", out, 0600)
				Expect(err).ToNot(HaveOccurred())

				stat, err := os.Stat(out)
				Expect(err).ToNot(HaveOccurred())
				if runtime.GOOS == "windows" {
					Expect(stat.Mode()).To(Equal(os.FileMode(0666)))
				} else {
					Expect(stat.Mode()).To(Equal(os.FileMode(0600)))
				}
				t, err := os.ReadFile(out)
				Expect(err).ToNot(HaveOccurred())
				claims = &StandardClaims{}
				pubK, _ := loadEd25519Seed("testdata/ed25519/signer.seed")
				err = ParseToken(string(t), claims, pubK)
				Expect(err).ToNot(HaveOccurred())
				Expect(claims.Issuer).To(Equal("ginkgo"))
			})
		})

		Describe("RSA", func() {
			It("Should correctly sign and save", func() {
				err = SaveAndSignTokenWithKeyFile(claims, "testdata/rsa/signer-key.pem", out, 0600)
				Expect(err).ToNot(HaveOccurred())

				stat, err := os.Stat(out)
				Expect(err).ToNot(HaveOccurred())
				if runtime.GOOS == "windows" {
					Expect(stat.Mode()).To(Equal(os.FileMode(0666)))
				} else {
					Expect(stat.Mode()).To(Equal(os.FileMode(0600)))
				}
				t, err := os.ReadFile(out)
				Expect(err).ToNot(HaveOccurred())
				claims = &StandardClaims{}
				err = ParseToken(string(t), claims, loadRSAPubKey("testdata/rsa/signer-public.pem"))
				Expect(err).ToNot(HaveOccurred())
				Expect(claims.Issuer).To(Equal("ginkgo"))
			})
		})
	})

	Describe("newStandardClaims", func() {
		It("Should create correct claims", func() {
			claims, err := newStandardClaims("ginkgo", ProvisioningPurpose, 0, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(claims.Issuer).To(Equal("ginkgo"))
			Expect(claims.Purpose).To(Equal(ProvisioningPurpose))
			Expect(claims.IssuedAt.Time).To(BeTemporally("~", time.Now(), time.Second))
			Expect(claims.ExpiresAt.Time).To(BeTemporally("~", time.Now().Add(time.Hour), time.Second))

			claims, err = newStandardClaims("ginkgo", ProvisioningPurpose, 5*time.Hour, true)
			Expect(err).ToNot(HaveOccurred())
			Expect(claims.Issuer).To(Equal("ginkgo"))
			Expect(claims.Purpose).To(Equal(ProvisioningPurpose))
			Expect(claims.Subject).To(Equal(string(ProvisioningPurpose)))
			Expect(claims.IssuedAt.Time).To(BeTemporally("~", time.Now(), time.Second))
			Expect(claims.ExpiresAt.Time).To(BeTemporally("~", time.Now().Add(5*time.Hour), time.Second))
		})
	})

	Describe("IsEncodedEd25519Key", func() {
		It("Should correctly detect based on length", func() {
			Expect(IsEncodedEd25519Key([]byte("1f5bcd09026ef84134d0963c17d6df388366a8767b418c209168dc8bb579f82b"))).To(BeTrue())
			Expect(IsEncodedEd25519Key([]byte("1f5bcd09026ef84134d0963c17d6df388366a8767b418c209168dc8bb579f82"))).To(BeFalse())
			Expect(IsEncodedEd25519Key([]byte("1f5bcd09026ef84134d0963c17d6df388366a8767b418c209168dc8bb579f82b2"))).To(BeFalse())
			Expect(IsEncodedEd25519Key([]byte(""))).To(BeFalse())
		})

		It("Should detect hex strings correctly", func() {
			var valid, invalid int

			pk := []byte("1f5bcd09026ef84134d0963c17d6df388366a8767b418c209168dc8bb579f82b")

			for i := 0; i < 256; i++ {
				pk[10] = byte(i)

				var isHex bool

				_, err := hex.DecodeString(string(pk))
				if err != nil {
					invalid++
				} else {
					isHex = true
					valid++
				}

				Expect(IsEncodedEd25519Key(pk)).To(Equal(isHex))
			}

			Expect(valid).To(BeNumerically(">", 1))
			Expect(invalid).To(BeNumerically(">", 1))
		})
	})
})

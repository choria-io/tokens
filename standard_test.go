// Copyright (c) 2022-2023, R.I. Pienaar and the Choria Project contributors
//
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/segmentio/ksuid"
)

var _ = Describe("StandardClaims", func() {
	var (
		c    *StandardClaims
		priK ed25519.PrivateKey
		pubK ed25519.PublicKey
		err  error
	)

	BeforeEach(func() {
		c, _ = newStandardClaims("ginkgo", "", time.Hour, false)
		pubK, priK, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).ToNot(HaveOccurred())

	})

	Describe("Chain Issuer", func() {
		Describe("ExpireTime", func() {
			It("Should handle all nil", func() {
				c.ExpiresAt = nil
				Expect(c.ExpireTime().IsZero()).To(BeTrue())
			})

			It("Should handle nil issuer exp", func() {
				c.ExpiresAt = jwt.NewNumericDate(time.Now())
				Expect(c.ExpireTime()).To(Equal(c.ExpiresAt.Time))
			})

			It("Should handle nil exp", func() {
				c.IssuerExpiresAt = jwt.NewNumericDate(time.Now())
				Expect(c.ExpireTime()).To(Equal(c.IssuerExpiresAt.Time))
			})

			It("Should use the issuer if before token", func() {
				c.IssuerExpiresAt = jwt.NewNumericDate(time.Now())
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
				Expect(c.ExpireTime()).To(Equal(c.IssuerExpiresAt.Time))
			})

			It("Should use the token if before issuer", func() {
				c.IssuerExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
				c.ExpiresAt = jwt.NewNumericDate(time.Now())
				Expect(c.ExpireTime()).To(Equal(c.ExpiresAt.Time))
			})
		})

		Describe("IsExpired", func() {
			It("Should detect expiry correctly", func() {
				c = &StandardClaims{}
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Minute))
				Expect(c.IsExpired()).To(BeFalse())
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Minute))
				Expect(c.IsExpired()).To(BeTrue())
			})
		})

		Describe("verifyIssuerExpiry", func() {
			BeforeEach(func() {
				c = &StandardClaims{}
				c.Issuer = "C-x.x"
				c.TrustChainSignature = "stub.sig"
				c.IssuerExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Minute))
			})

			It("Should only verify on tokens issues by a chain issues", func() {
				c.Issuer = "I-x.x"
				Expect(c.verifyIssuerExpiry(false)).To(BeTrue())
				Expect(c.verifyIssuerExpiry(true)).To(BeFalse())
			})

			It("Should detect missing tcs", func() {
				c.TrustChainSignature = ""
				Expect(c.verifyIssuerExpiry(true)).To(BeFalse())
				Expect(c.verifyIssuerExpiry(false)).To(BeTrue())
			})

			It("Should detect missing issuer expiry", func() {
				c.IssuerExpiresAt = nil
				Expect(c.verifyIssuerExpiry(true)).To(BeFalse())
				Expect(c.verifyIssuerExpiry(false)).To(BeTrue())
			})

			It("Should correctly detect expiry", func() {
				Expect(c.verifyIssuerExpiry(true)).To(BeTrue())
				Expect(c.verifyIssuerExpiry(false)).To(BeTrue())

				c.IssuerExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Minute))
				Expect(c.verifyIssuerExpiry(true)).To(BeFalse())
				Expect(c.verifyIssuerExpiry(false)).To(BeFalse())
			})
		})

		Describe("SetChainIssuer", func() {
			It("Should require basic data", func() {
				ci := &ClientIDClaims{}
				Expect(c.SetChainIssuer(ci)).To(MatchError("id not set"))

				ci.ID = "x"
				Expect(c.SetChainIssuer(ci)).To(MatchError("public key not set"))
			})

			It("Should set the correct issuer", func() {
				ci := &ClientIDClaims{}
				ci.ID = ksuid.New().String()
				ci.PublicKey = hex.EncodeToString(pubK[:])
				ci.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
				Expect(c.SetChainIssuer(ci)).To(Succeed())
				Expect(c.Issuer).To(Equal(fmt.Sprintf("C-%s.%s", ci.ID, ci.PublicKey)))
			})
		})

		Describe("ChainIssuerData", func() {
			It("Should require minimal data", func() {
				c.ID = ""
				_, err = c.ChainIssuerData("x")
				Expect(err).To(MatchError("id not set"))

				c.ID = ksuid.New().String()
				c.Issuer = ""
				_, err = c.ChainIssuerData("x")
				Expect(err).To(MatchError("issuer not set"))

				c.Issuer = "X-Issuer"
				_, err = c.ChainIssuerData("x")
				Expect(err).To(MatchError("invalid issuer prefix"))

				c.Issuer = "C-x"
				_, err = c.ChainIssuerData("x")
				Expect(err).To(MatchError("invalid issuer data"))
			})

			It("Should issue the correct data", func() {
				ci := &ClientIDClaims{}
				ci.ID = ksuid.New().String()
				ci.PublicKey = hex.EncodeToString(pubK[:])
				ci.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
				Expect(c.SetChainIssuer(ci)).To(Succeed())

				dat, err := c.ChainIssuerData("x")
				Expect(err).ToNot(HaveOccurred())
				Expect(dat).To(Equal([]byte(fmt.Sprintf("%s.x", c.ID))))
			})
		})

		Describe("IsSignedByIssuer", func() {
			It("Should detect badly formed issuers", func() {
				c.Issuer = "C-x"
				c.PublicKey = hex.EncodeToString(pubK)
				c.TrustChainSignature = "x"
				c.ID = ksuid.New().String()
				c.IssuerExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))

				ok, _, err := c.IsSignedByIssuer(pubK)
				Expect(err).To(MatchError("invalid issuer content"))
				Expect(ok).To(BeFalse())

				c.Issuer = "C-.x"
				ok, _, err = c.IsSignedByIssuer(pubK)
				Expect(err).To(MatchError("invalid id in issuer"))
				Expect(ok).To(BeFalse())

				c.Issuer = "C-y."
				ok, _, err = c.IsSignedByIssuer(pubK)
				Expect(err).To(MatchError("invalid public key in issuer"))
				Expect(ok).To(BeFalse())

				c.Issuer = "C-!.y"
				ok, _, err = c.IsSignedByIssuer(pubK)
				Expect(err).To(MatchError("invalid public key in issuer data"))
				Expect(ok).To(BeFalse())
			})

			It("Should detect badly formed trust chain sigs", func() {
				c.Issuer = "C-x." + hex.EncodeToString(pubK)
				c.PublicKey = hex.EncodeToString(pubK)
				c.TrustChainSignature = "X"
				c.IssuerExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))

				ok, _, err := c.IsSignedByIssuer(pubK)
				Expect(err).To(MatchError("invalid trust chain signature"))
				Expect(ok).To(BeFalse())

				c.TrustChainSignature = "."
				ok, _, err = c.IsSignedByIssuer(pubK)
				Expect(err).To(MatchError("invalid trust chain signature"))
				Expect(ok).To(BeFalse())

				c.TrustChainSignature = "foo.!!"
				ok, _, err = c.IsSignedByIssuer(pubK)
				Expect(err).To(MatchError("invalid signature in chain signature: encoding/hex: invalid byte: U+0021 '!'"))
				Expect(ok).To(BeFalse())
			})

			It("Should detect incorrect signatures", func() {
				// the org issuer
				issuePubK, issuerPriK, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				handlerPubK, _, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				userPubK, _, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				// the handler signed by the org issuer
				handler, err := NewClientIDClaims("choria=handler", nil, "", nil, "", "", time.Minute, nil, handlerPubK)
				Expect(err).ToNot(HaveOccurred())
				handler.SetOrgIssuer(issuePubK)
				hdat, err := handler.OrgIssuerChainData()
				Expect(err).ToNot(HaveOccurred())
				hsig, err := ed25519Sign(issuerPriK, hdat)
				Expect(err).ToNot(HaveOccurred())
				handler.TrustChainSignature = "invalid"

				// it looks good so it passes but with verify fails
				Expect(handler.IsChainedIssuer(false)).To(BeTrue())
				Expect(handler.IsChainedIssuer(true)).To(BeFalse())

				handler.TrustChainSignature = hex.EncodeToString(hsig)

				// now it looks good and it is good
				Expect(handler.IsChainedIssuer(false)).To(BeTrue())
				Expect(handler.IsChainedIssuer(true)).To(BeTrue())

				// a user issued by the handler
				user, err := NewClientIDClaims("choria=user", nil, "", nil, "", "", time.Minute, nil, userPubK)
				Expect(err).ToNot(HaveOccurred())
				Expect(user.SetChainIssuer(handler)).To(Succeed())
				user.SetChainUserTrustSignature(handler, []byte("invalid sig"))
				ok, _, err := user.IsSignedByIssuer(issuePubK)
				Expect(err).To(MatchError("invalid chain signature"))
				Expect(ok).To(BeFalse())
			})

			It("Should reject tokens with fake chain issuer credentials", func() {
				// the real org issuer - attacker does NOT have this private key
				orgPubK, _, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				// attacker generates their own keypair
				attackerPubK, attackerPriK, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				// attacker creates a fake handler using their own key
				fakeHandler, err := NewClientIDClaims("choria=fake_handler", nil, "", nil, "", "", time.Minute, nil, attackerPubK)
				Expect(err).ToNot(HaveOccurred())

				// attacker fabricates a TCS - NOT signed by the real org issuer
				// they sign it with their own key instead
				fakeTCSData := fmt.Sprintf("%s.%s", fakeHandler.ID, hex.EncodeToString(attackerPubK))
				fakeTCSSig, err := ed25519Sign(attackerPriK, []byte(fakeTCSData))
				Expect(err).ToNot(HaveOccurred())
				fakeHandler.TrustChainSignature = hex.EncodeToString(fakeTCSSig)

				// attacker creates a user token issued by the fake handler
				userPubK, _, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())
				user, err := NewClientIDClaims("choria=victim", nil, "", nil, "", "", time.Minute, nil, userPubK)
				Expect(err).ToNot(HaveOccurred())
				Expect(user.SetChainIssuer(fakeHandler)).To(Succeed())

				// attacker signs the user data with their own private key
				udat, err := user.ChainIssuerData(fakeHandler.TrustChainSignature)
				Expect(err).ToNot(HaveOccurred())
				usig, err := ed25519Sign(attackerPriK, udat)
				Expect(err).ToNot(HaveOccurred())
				user.SetChainUserTrustSignature(fakeHandler, usig)

				// this MUST fail - the org issuer (orgPubK) never signed the chain issuer's credentials
				ok, _, err := user.IsSignedByIssuer(orgPubK)
				Expect(err).To(HaveOccurred())
				Expect(ok).To(BeFalse(), "forged chain token should not pass verification against org issuer")
			})

			It("Should detect correct signatures", func() {
				// the org issuer
				issuePubK, issuerPriK, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				handlerPubK, handlerPrik, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				userPubK, _, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				// the handler signed by the org issuer
				handler, err := NewClientIDClaims("choria=handler", nil, "", nil, "", "", time.Minute, nil, handlerPubK)
				Expect(err).ToNot(HaveOccurred())
				handler.SetOrgIssuer(issuePubK)
				hdat, err := handler.OrgIssuerChainData()
				Expect(err).ToNot(HaveOccurred())
				hsig, err := ed25519Sign(issuerPriK, hdat)
				Expect(err).ToNot(HaveOccurred())
				handler.TrustChainSignature = hex.EncodeToString(hsig)

				// a user issued by the handler
				user, err := NewClientIDClaims("choria=user", nil, "", nil, "", "", time.Minute, nil, userPubK)
				Expect(err).ToNot(HaveOccurred())
				Expect(user.SetChainIssuer(handler)).To(Succeed())
				udat, err := user.ChainIssuerData(handler.TrustChainSignature)
				Expect(err).ToNot(HaveOccurred())
				usig, err := ed25519Sign(handlerPrik, udat)
				Expect(err).ToNot(HaveOccurred())
				user.SetChainUserTrustSignature(handler, usig)
				ok, _, err := user.IsSignedByIssuer(issuePubK)
				Expect(err).ToNot(HaveOccurred())
				Expect(ok).To(BeTrue())
			})
		})
	})

	Describe("AddOrgIssuerData", func() {
		It("Should fail without required data", func() {
			c.ID = ""
			err = c.AddOrgIssuerData(priK)
			Expect(err).To(MatchError("no token id set"))
		})

		It("Should set issuer and trust chain signature", func() {
			c.PublicKey = hex.EncodeToString(pubK)
			err = c.AddOrgIssuerData(priK)
			Expect(err).ToNot(HaveOccurred())

			Expect(c.Issuer).To(Equal(fmt.Sprintf("I-%s", hex.EncodeToString(pubK))))
			Expect(c.TrustChainSignature).ToNot(BeEmpty())
			Expect(c.IsChainedIssuer(true)).To(BeTrue())
		})
	})

	Describe("AddChainIssuerData", func() {
		It("Should fail with invalid chain issuer", func() {
			ci := &ClientIDClaims{}
			err = c.AddChainIssuerData(ci, priK)
			Expect(err).To(MatchError("id not set"))
		})

		It("Should set chain issuer data correctly", func() {
			issuePubK, issuerPriK, err := ed25519.GenerateKey(rand.Reader)
			Expect(err).ToNot(HaveOccurred())

			handlerPubK, handlerPriK, err := ed25519.GenerateKey(rand.Reader)
			Expect(err).ToNot(HaveOccurred())

			userPubK, _, err := ed25519.GenerateKey(rand.Reader)
			Expect(err).ToNot(HaveOccurred())

			// create a chain issuer (handler) signed by org issuer
			handler, err := NewClientIDClaims("choria=handler", nil, "", nil, "", "", time.Minute, nil, handlerPubK)
			Expect(err).ToNot(HaveOccurred())
			err = handler.AddOrgIssuerData(issuerPriK)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.IsChainedIssuer(true)).To(BeTrue())

			// create a user issued by the handler using AddChainIssuerData
			user, err := NewClientIDClaims("choria=user", nil, "", nil, "", "", time.Minute, nil, userPubK)
			Expect(err).ToNot(HaveOccurred())
			err = user.AddChainIssuerData(handler, handlerPriK)
			Expect(err).ToNot(HaveOccurred())

			// verify the chain
			ok, _, err := user.IsSignedByIssuer(issuePubK)
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})
	})

	Describe("SetChainIssuerTrustSignature", func() {
		It("Should set the trust chain signature", func() {
			sig := []byte("test signature data")
			c.SetChainIssuerTrustSignature(sig)
			Expect(c.TrustChainSignature).To(Equal(hex.EncodeToString(sig)))
		})
	})

	Describe("IsChainedIssuer", func() {
		It("Should fail without trust chain signature", func() {
			c.TrustChainSignature = ""
			Expect(c.IsChainedIssuer(false)).To(BeFalse())
		})

		It("Should fail without org issuer prefix", func() {
			c.TrustChainSignature = "x"
			c.Issuer = "C-x"
			Expect(c.IsChainedIssuer(false)).To(BeFalse())
		})

		It("Should return true without verify when data looks valid", func() {
			c.TrustChainSignature = "x"
			c.Issuer = "I-x"
			Expect(c.IsChainedIssuer(false)).To(BeTrue())
		})

		It("Should fail verify with invalid hex in issuer", func() {
			c.TrustChainSignature = "x"
			c.Issuer = "I-!invalid!"
			c.PublicKey = "x"
			Expect(c.IsChainedIssuer(true)).To(BeFalse())
		})

		It("Should fail verify with invalid hex in tcs", func() {
			c.PublicKey = hex.EncodeToString(pubK)
			c.Issuer = fmt.Sprintf("I-%s", hex.EncodeToString(pubK))
			c.TrustChainSignature = "!invalid!"
			Expect(c.IsChainedIssuer(true)).To(BeFalse())
		})
	})

	Describe("Organization Issuer", func() {
		Describe("IsSignedByIssuer", func() {
			It("Should expect minimally correct data", func() {
				check := func(pk ed25519.PublicKey, expect error) {
					ok, _, err := c.IsSignedByIssuer(pk)
					if expect == nil && !ok {
						Fail(fmt.Sprintf("Expected to be ok but got %v", err))
					}

					Expect(err).To(MatchError(expect))
					Expect(ok).To(BeFalse())
				}

				iss := c.Issuer
				c.Issuer = ""
				check(nil, fmt.Errorf("no issuer set"))
				c.Issuer = iss

				check(nil, fmt.Errorf("no public key set"))
				c.PublicKey = hex.EncodeToString(pubK)

				check(pubK, fmt.Errorf("no trust chain signature set"))
				c.TrustChainSignature = "x"

				c.IssuedAt = nil
				check(pubK, fmt.Errorf("no issued time set"))
				c.IssuedAt = jwt.NewNumericDate(time.Time{})
				check(pubK, fmt.Errorf("no issued time set"))
				c.IssuedAt = c.NotBefore

				c.ExpiresAt = nil
				check(pubK, fmt.Errorf("no expires set"))
				c.ExpiresAt = jwt.NewNumericDate(time.Time{})
				check(pubK, fmt.Errorf("no expires set"))
				c.ExpiresAt = jwt.NewNumericDate(c.IssuedAt.Add(time.Hour))

				c.ID = ""
				check(pubK, fmt.Errorf("id not set"))

				c.ID = "x"
				check(pubK, fmt.Errorf("invalid ksuid format"))

				kid, _ := ksuid.NewRandomWithTime(time.Now().Add(time.Hour))
				c.ID = kid.String()
				check(pubK, fmt.Errorf("id is not based on issued time"))

				kid, _ = ksuid.NewRandomWithTime(c.IssuedAt.Time)
				c.ID = kid.String()
				check(pubK, fmt.Errorf("unsupported issuer format")) // passed validation state
			})

			It("Should detect invalid issuers", func() {
				c.Issuer = "issuer"
				c.PublicKey = hex.EncodeToString(pubK)
				c.TrustChainSignature = "x"
				c.ID = ksuid.New().String()

				ok, _, err := c.IsSignedByIssuer(pubK)
				Expect(err).To(MatchError("unsupported issuer format"))
				Expect(ok).To(BeFalse())
			})

			It("Should detect invalid signatures", func() {
				c.PublicKey = hex.EncodeToString(pubK)
				c.Issuer = fmt.Sprintf("I-%s", c.PublicKey)
				c.TrustChainSignature = "X"
				c.ID = ksuid.New().String()
				ok, _, err := c.IsSignedByIssuer(pubK)
				Expect(err).To(MatchError("invalid trust chain signature: encoding/hex: invalid byte: U+0058 'X'"))
				Expect(ok).To(BeFalse())
			})

			It("Should detect wrong signatures", func() {
				c.PublicKey = hex.EncodeToString(pubK)
				c.Issuer = fmt.Sprintf("I-%s", c.PublicKey)
				c.ID = ksuid.New().String()

				sig, err := ed25519Sign(priK, []byte("wrong"))
				Expect(err).ToNot(HaveOccurred())
				c.TrustChainSignature = hex.EncodeToString(sig)

				ok, _, err := c.IsSignedByIssuer(pubK)
				Expect(err).ToNot(HaveOccurred())
				Expect(ok).To(BeFalse())
			})

			It("Should detect correct signatures", func() {
				c.PublicKey = hex.EncodeToString(pubK)
				c.Issuer = fmt.Sprintf("I-%s", c.PublicKey)
				c.ID = ksuid.New().String()

				dat, err := c.OrgIssuerChainData()
				Expect(err).ToNot(HaveOccurred())

				sig, err := ed25519Sign(priK, dat)
				Expect(err).ToNot(HaveOccurred())
				c.TrustChainSignature = hex.EncodeToString(sig)

				ok, pk, err := c.IsSignedByIssuer(pubK)
				Expect(err).ToNot(HaveOccurred())
				Expect(pk).To(Equal(pubK))
				Expect(ok).To(BeTrue())
			})
		})

		Describe("SetOrgIssuer", func() {
			It("Should set the correct issuer", func() {
				pubK, _, err := ed25519.GenerateKey(rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				c.SetOrgIssuer(pubK)
				Expect(c.Issuer).To(Equal(fmt.Sprintf("I-%x", pubK)))
			})
		})

		Describe("OrgIssuerChainData", func() {
			It("Should fail for no ID", func() {
				c.ID = ""
				d, err := c.OrgIssuerChainData()
				Expect(d).To(HaveLen(0))
				Expect(err).To(MatchError("no token id set"))
			})

			It("Should fail for no PublicKey", func() {
				d, err := c.OrgIssuerChainData()
				Expect(d).To(HaveLen(0))
				Expect(err).To(MatchError("no public key set"))
			})

			It("Should create the correct data", func() {
				c.ID = "id"
				c.PublicKey = "pubk"
				d, err := c.OrgIssuerChainData()
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("id.pubk")))
			})
		})
	})
})

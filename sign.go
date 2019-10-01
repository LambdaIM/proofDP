// Copyright (c) 2019 lambdastorage.com
// --------
// This file is part of The proofDP library.
//
// The proofDP is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The proofDP is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the proofDP. If not, see <http://www.gnu.org/licenses/>.

package proofDP

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/LambdaIM/proofDP/math"
	"golang.org/x/crypto/scrypt"
)

const (
	scryptN = 32768
	scryptR = 8
	scryptP = 1
	scryptL = 32
)

// Here I implement a pairing-based BLS DSA. However, the performance of
// this implementation is not that good. 1024 times sign-verification takes
// around 140+ seconds which is a little bit too much.

// Signature is a wrapper of the inner type
type Signature = math.EllipticPoint

// SignPubKey is the public key for PDP signature verification
type SignPubKey struct {
	key math.EllipticPoint
}

// SignPrivKey is the private key for PDP signature
type SignPrivKey struct {
	key math.GaloisElem
	Pk  SignPubKey
}

// GenerateSignPrivKeyFromSecret creates a new SignPrivKey instance
func GenerateSignPrivKeyFromSecret(secret []byte) (*SignPrivKey, error) {
	salt := make([]byte, scryptR)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	saltedSecret, err := scrypt.Key(secret, salt, scryptN, scryptR, scryptP, scryptL)
	if err != nil {
		return nil, err
	}

	k := math.HashToGaloisElem(saltedSecret)
	return &SignPrivKey{
		key: k,
		Pk: SignPubKey{
			key: math.EllipticPow(math.GetGenerator(), k),
		},
	}, nil
}

// Sign generates a signature using SignPrivKey instance on
// given hash
func (sk *SignPrivKey) Sign(h [sha256.Size]byte) Signature {
	d := math.HashToEllipticPt(h[:])
	return math.EllipticPow(d, sk.key)
}

// VerifySignature validates if a signature is signed using 'pk'-responding
// SignPrivKey instance on the given hash 'h'.
func VerifySignature(s Signature, h [sha256.Size]byte, pk SignPubKey) bool {
	lhs := math.BiLinearMap(s, math.GetGenerator())

	d := math.HashToEllipticPt(h[:])
	rhs := math.BiLinearMap(d, pk.key)

	return math.QuadraticEqual(lhs, rhs)
}

// TODO: implement the github.com/tendermint/crypto.PrivKey & PubKey interfaces

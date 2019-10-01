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
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	signTestRound = 32
)

func TestBLSScheme(t *testing.T) {
	for i := 0; i < signTestRound; i++ {
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		assert.NoError(t, err)

		sk, err := GenerateSignPrivKeyFromSecret(secret)
		assert.NoError(t, err)

		message := make([]byte, 128)
		_, err = rand.Read(message)
		assert.NoError(t, err)

		hash := sha256.Sum256(message)
		signature := sk.Sign(hash)

		assert.True(t, VerifySignature(signature, hash, sk.Pk))
	}
}

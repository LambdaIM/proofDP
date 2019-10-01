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
	"os"
	"testing"

	"github.com/LambdaIM/proofDP/math"
	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

const (
	sampleFilePath = "math/quadratic_test.go"

	proofDPTestRound = 1
)

func TestProofDPScheme(t *testing.T) {
	for i := 0; i < proofDPTestRound; i++ {
		ssk := secp256k1.GenPrivKey()
		sp, err := GeneratePrivateParams(ssk)
		assert.NoError(t, err)

		u, err := math.RandEllipticPt()
		assert.NoError(t, err)
		pp := sp.GeneratePublicParams(u)

		file, err := os.OpenFile(sampleFilePath, os.O_RDONLY, 0644)
		assert.NoError(t, err)
		tag, err := GenTag(sp, pp, []byte(sampleFilePath), file)
		assert.NoError(t, err)
		file.Close()

		chal, err := GenChal([]byte(sampleFilePath))
		assert.NoError(t, err)

		file, err = os.OpenFile(sampleFilePath, os.O_RDONLY, 0644)
		assert.NoError(t, err)
		proof, err := Prove(pp, chal, tag, file)
		assert.NoError(t, err)
		file.Close()

		assert.True(t, VerifyProof(pp, chal, proof))
	}
}

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
	"bytes"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/LambdaIM/proofDP/math"
	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

// psuedo-constant
var sampleFiles = []string{
	"math/quadratic_test.go",
}

func TestProofDPScheme(t *testing.T) {
	for _, sampleFilePath := range sampleFiles {
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

func TestPDPAgainstChanges(t *testing.T) {
	for _, sampleFilePath := range sampleFiles {
		ssk := secp256k1.GenPrivKey()
		sp, err := GeneratePrivateParams(ssk)
		assert.NoError(t, err)

		u, err := math.RandEllipticPt()
		assert.NoError(t, err)
		pp := sp.GeneratePublicParams(u)

		data, err := ioutil.ReadFile(sampleFilePath)
		assert.NoError(t, err)

		tagBuf := bytes.NewReader(data)
		tag, err := GenTag(sp, pp, []byte(sampleFilePath), tagBuf)
		assert.NoError(t, err)

		chal, err := GenChal([]byte(sampleFilePath))
		assert.NoError(t, err)

		passPrfBuf := bytes.NewReader(data)
		passPrf, err := Prove(pp, chal, tag, passPrfBuf)
		assert.NoError(t, err)

		// make sure the unchanged content works
		assert.True(t, VerifyProof(pp, chal, passPrf))

		// a bit flip in random position
		rand.Seed(time.Now().UnixNano())
		idx := rand.Intn(len(data))
		data[idx] ^= byte(1 << 7)

		failPrfBuf := bytes.NewReader(data)
		failPrf, err := Prove(pp, chal, tag, failPrfBuf)
		assert.NoError(t, err)

		// make sure the changed content fails
		assert.False(t, VerifyProof(pp, chal, failPrf))
	}
}

func TestPDPAgainstLoss(t *testing.T) {
	for _, sampleFilePath := range sampleFiles {
		ssk := secp256k1.GenPrivKey()
		sp, err := GeneratePrivateParams(ssk)
		assert.NoError(t, err)

		u, err := math.RandEllipticPt()
		assert.NoError(t, err)
		pp := sp.GeneratePublicParams(u)

		data, err := ioutil.ReadFile(sampleFilePath)
		assert.NoError(t, err)

		tagBuf := bytes.NewReader(data)
		tag, err := GenTag(sp, pp, []byte(sampleFilePath), tagBuf)
		assert.NoError(t, err)

		chal, err := GenChal([]byte(sampleFilePath))
		assert.NoError(t, err)

		passPrfBuf := bytes.NewReader(data)
		passPrf, err := Prove(pp, chal, tag, passPrfBuf)
		assert.NoError(t, err)

		// make sure the unchanged content works
		assert.True(t, VerifyProof(pp, chal, passPrf))

		// lose the last byte
		incompleteData := make([]byte, len(data)-1)
		copy(incompleteData, data[:len(data)-1])

		failPrfBuf := bytes.NewReader(incompleteData)
		failPrf, err := Prove(pp, chal, tag, failPrfBuf)
		assert.NoError(t, err)

		// make sure the incomplete content fails
		assert.False(t, VerifyProof(pp, chal, failPrf))
	}
}

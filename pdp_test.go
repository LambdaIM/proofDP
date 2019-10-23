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
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/LambdaIM/proofDP/math"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

// psuedo-constant
var sampleFiles = []string{
	"math/elliptic_test.go",
	"math/galois_test.go",
	"math/pairing_test.go",
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
		tag, err := GenTag(sp, pp, []byte(strconv.Itoa(111)), file)
		assert.NoError(t, err)
		file.Close()

		chal, err := GenChal([]byte(strconv.Itoa(111)))
		assert.NoError(t, err)

		file, err = os.OpenFile(sampleFilePath, os.O_RDONLY, 0644)
		assert.NoError(t, err)
		proof, err := Prove(pp, chal, tag, file)
		assert.NoError(t, err)
		file.Close()

		require.True(t, VerifyProof(pp, chal, proof))
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

func TestSampleValue(t *testing.T) {
	samplePPStr := "lEbWlt9HsuIbNoae9GKi18wjUlDOfGwsyQECXZT44AgH4278Wiz63Ur4WU+eHGJNcJMFgB/EVpau+SOCe1oPsC2LnRYqvpkzZR+gDW7D0F10XQuJZkC0t2F2w4erhI+bNaJCjoCBfjTLfxd3s3PE7ABoezVJxMU97SMya2NNkts=,Ayppy9ovSnxVrTVqmmaanuV5NI3dYCjKxlQ+JF33BRqZ9SCgPBIP/NnfzAQbqR8lpYpAbSL8uZQDNeqXDAXQ2EihIk8hGN4H2sEK2e7OgIeLIJ/bANDg3hOAevZ6Fgs4beOWnGr7hlFERVXy/uWT2bkwqNctizvd1mYoPPK8Yx0=,XkZ2q7tc+MsEOSdjfYyT7A8vV6Jj2u8XkbSfu2ZL/mUP/eLdnjBy0UAG2QFrYlAf8ACiM3n0Yg93NiMaPJx93Yinm7N6KBXNW9Dse8C4ZTo5TUJfjvIp+YU3ESzhrUdiorEQKsTzoZfXp0QZXlBrUwlLqiPXh5sjZ5ZbUmmGUyI="
	pp, err := ParsePublicParams(samplePPStr)
	require.NoError(t, err)

	sampleChalStr := "NDI=,BtpUiNsZIyc4vLYBVIx3K3cF7fY="
	chal, err := ParseChal(sampleChalStr)
	require.NoError(t, err)

	sampleProofStr := "PF2IOBHOwPrxDxWghgq+55mLbFE=,Q7+FLPCpV50OLadfuYqIm6egFl7Fi7s3mm4cWhDYMyWG8NFiIUW0mctw+CCdIQD8PzF00LE5MdPJsR6C3Ant2B+BDmtIY4ItRDD5zLFpuO1ZBYSxZTSo26OG5UsZeozGqygzvpPQq7KdhVQazNya1IEGhpiC//5YJEXtockQneI=,KBH/X8DQSqfrBHeLgOLyB805rpxhSidxT64LaPklO0Rw+jZQAjZNEQsEDVo9pcFhjkR9yvzq8W03Un7iYGIP83PkjVXduAWzRnV5k2aHVO9lS5oUHE7H1t9icTxmtQG4Q68/JtCeJuOsko0/DVLNj+bxOzQAV5KXDvf5R86uwZk="
	proof, err := ParseProof(sampleProofStr)
	require.NoError(t, err)

	fmt.Printf("%t\n", VerifyProof(pp, chal, proof))
}

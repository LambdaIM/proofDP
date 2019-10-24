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
		sp, err := GeneratePrivateParams(ssk.Bytes())
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
		sp, err := GeneratePrivateParams(ssk.Bytes())
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
		sp, err := GeneratePrivateParams(ssk.Bytes())
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
	samplePPStr := "BGigSMkCItBCwTqemMCtmoDKXVMVCdVwUZXZVf2hPvPNO2DLtQn13bI/CxvIaIpTEiAzj0zr7oe0lzhNQKyE5kZnF+MtgNDOscJwBIdnJHPXdDfCl8svh35eoGiq/EVOo+szhGkFL4sN+JVzKLHNVOcwSZBff6sbmPH8XB4t/9o=,D0aNIV3hRTRHROopG2eTTcEf+WSIe/N5MEix5rHW4nXpU+GdafsCNyohik22pDtpS5j0KWKDushRECekpWhNDRIZTvVhHQLZl1j1b9xGnbVthpZlCc/0bwkJ47681owhWxeFunSqhx657M5+RbsnHoFcdD7FCxwvq5noqiI/KRE=,aketewWR8nYgnoJc/SCYCR7avZhMmx32O8Ja3G1hQztNNImCRAFAxXEFJ3fIzSkwRrsY0Z8XnVrjn6m6KgYgv5Bfac3lyrlbBR2vNwjaqyyHmimPLqCcKJ9qOCTieAtd6GHRYDrgsMP7iLrpedvetRtgjS3EQQgSwnYaava2ry8="
	pp, err := ParsePublicParams(samplePPStr)
	require.NoError(t, err)

	sampleChalStr := "MTk=,U6jngYuZCWQv0NlqGklQQISTQrY="
	chal, err := ParseChal(sampleChalStr)
	require.NoError(t, err)

	sampleProofStr := "CvnoxLVzu8Axk73zF1rA7BUD0Yc=,NpqB/3O97gOIADhfaafwGu5aM9oYGV/018orjMI2XUp3nvJ41FiVVWCmRUl80HMloiPbuHPl5U5QINiZOyqRbGMvxelvuQuP0R9FIg54NZiVNAfX4F6G3RnWS2LppGCcbhDOmyCo/zALi1JugZpMJqU3k3rJFIenZxY+HqZbH+Q=,dEdSDvEsVL2DteF9TSchgsSMIznNtH0JEO4sZFRwyg4EEBHKcWXxBmztus2Ga0dTLItEnElzE/lyzocfPM6py5L06IT/iEhojvjed+ACXbpQ2Kphv4fCF5Df+TUlq/h9MNZFQAJpNilyB0VgjlUhkeKj46cEmKMdhI7lanJ7vEU="
	proof, err := ParseProof(sampleProofStr)
	require.NoError(t, err)

	fmt.Printf("%t\n", VerifyProof(pp, chal, proof))
}

package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	pdp "github.com/LambdaIM/proofDP"
	"github.com/LambdaIM/proofDP/math"
)

func getRandContent(l int) []byte {
	res := make([]byte, l)
	_, err := rand.Read(res)
	if err != nil {
		panic(err)
	}
	return res
}

const (
	secretLen = 32
	dataLen   = 4096

	testRound = 10000000
)

func main() {
	for i := 0; i < testRound; i++ {
		secret := getRandContent(secretLen)
		sp, err := pdp.GeneratePrivateParams(secret)
		if err != nil {
			panic(fmt.Errorf("%d: %s", i, err.Error()))
		}

		u, err := math.RandEllipticPt()
		if err != nil {
			panic(fmt.Errorf("%d: %s", i, err.Error()))
		}
		pp := sp.GeneratePublicParams(u)

		data := getRandContent(dataLen)
		dataReader := bytes.NewReader(data)
		tag, err := pdp.GenTag(sp, pp, int64(i), dataReader)
		if err != nil {
			panic(fmt.Errorf("%d: %s", i, err.Error()))
		}

		chal, err := pdp.GenChal(int64(i))
		if err != nil {
			panic(fmt.Errorf("%d: %s", i, err.Error()))
		}

		dataReader = bytes.NewReader(data)
		proof, err := pdp.Prove(pp, chal, tag, dataReader)
		if err != nil {
			panic(fmt.Errorf("%d: %s", i, err.Error()))
		}

		if pdp.VerifyProof(pp, chal, proof) {
			fmt.Printf("%d passed\n", i)
		} else {
			fmt.Printf("%d failed\n", i)
		}
	}
}

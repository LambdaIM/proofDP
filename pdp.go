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
	"fmt"
	"io"

	"github.com/LambdaIM/proofDP/math"
	"github.com/tendermint/tendermint/crypto"
	"golang.org/x/crypto/scrypt"
)

// constant
const (
	errUnsupportedDSASchemeFmt = "Given DSA scheme is not supported yet: %d"
	errGeneratePrivateParamFmt = "Failed to generate PrivateParams: %s"
	errGenerateDataTagFmt      = "Failed to generate tag for given data (index:%s): %s"
	errGenerateDataChalFmt     = "Failed to generate challenge for given data (index:%s): %s"
	errProveFmt                = "Failed to prove against challenge (index:%s): %s"
)

// PublicParams holds the public paramters of a specific PDP proof.
// Note that there may be multiple PublicParams instance coresponding
// to the same PrivateParams.
type PublicParams struct {
	spk crypto.PubKey
	v   math.EllipticPoint
	u   math.EllipticPoint
	e   math.QuadraticElem
}

// PrivateParams holds the private parameters of a specific PDP proof.
// Note a PrivateParams instance can be used to validate multiple
// PublicParams's proof.
type PrivateParams struct {
	ssk crypto.PrivKey
	x   math.GaloisElem
}

// Tag is the product of GenTag & a param of the VerifyProof
type Tag = math.EllipticPoint

// Chal wraps a validator created random value & corespoding idx
type Chal struct {
	idx []byte
	nu  math.GaloisElem
}

// Proof is the product of Prove
type Proof struct {
	miu   math.GaloisElem
	sigma math.EllipticPoint
	r     math.QuadraticElem
}

// GeneratePrivateParams returns the PrivateParams instance created using
// given crypto.PrivKey
func GeneratePrivateParams(sk crypto.PrivKey) (*PrivateParams, error) {
	salt := make([]byte, scryptR)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf(errGeneratePrivateParamFmt, err.Error())
	}

	saltedKey, err := scrypt.Key(sk.Bytes(), salt, scryptN, scryptR, scryptP, scryptL)
	if err != nil {
		return nil, fmt.Errorf(errGeneratePrivateParamFmt, err.Error())
	}

	return &PrivateParams{
		ssk: sk,
		x:   math.HashToGaloisElem(saltedKey),
	}, nil
}

// GeneratePublicParams returns a PublicParams instance generated using
// the given elliptic curve point 'u'
func (sp *PrivateParams) GeneratePublicParams(u math.EllipticPoint) *PublicParams {
	v := math.EllipticPow(math.GetGenerator(), sp.x)
	return &PublicParams{
		spk: sp.ssk.PubKey(),
		v:   v,
		u:   u,
		e:   math.BiLinearMap(u, v),
	}
}

// GenTag calculates the tag for given 'data' & 'idx'. Since the 'data' block may
// be too huge to load into memory, a SHA256 digest is applied here.
// Note that 'idx' here is actually refers to the (Fid||index) parameter in PDP paper.
func GenTag(sp *PrivateParams, pp *PublicParams, idx []byte, data io.Reader) (Tag, error) {
	hasher := sha256.New() // a singleton hasher maybe?
	if _, err := io.Copy(hasher, data); err != nil {
		return Tag{}, fmt.Errorf(errGenerateDataTagFmt, string(idx), err.Error())
	}
	m := math.BytesToGaloisElem(hasher.Sum(nil))

	t := math.HashToEllipticPt(idx)
	t = math.EllipticMul(t, math.EllipticPow(pp.u, m))
	return math.EllipticPow(t, sp.x), nil
}

// GenChal created a challenge instance for given 'idx'.
// Note that 'idx' here is actually refers to the (Fid||index) parameter in PDP paper.
// Also, GenChal creates just *ONE* challenge against the given 'idx'. According to
// the original paper, there should be a set of challenge against *ONE* file, which,
// however, is not going well with Lambda's system design.
func GenChal(idx []byte) (Chal, error) {
	nu, err := math.RandGaloisElem()
	if err != nil {
		return Chal{}, fmt.Errorf(errGenerateDataChalFmt, string(idx), err.Error())
	}
	return Chal{
		idx: idx,
		nu:  nu,
	}, nil
}

// Prove created a Proof instance against the given challenge & the local storage.
// Note that in this implementation a Chal instance contains only *ONE* pair of
// challenge target index & coresponding random value.
func Prove(pp *PublicParams, c Chal, t Tag, data io.Reader) (Proof, error) {
	rand, err := math.RandGaloisElem()
	if err != nil {
		return Proof{}, fmt.Errorf(errProveFmt, string(c.idx), err.Error())
	}
	r := math.QuadraticPow(pp.e, rand)

	hasher := sha256.New()
	if _, err := io.Copy(hasher, data); err != nil {
		return Proof{}, fmt.Errorf(errProveFmt, string(c.idx), err.Error())
	}
	m := math.BytesToGaloisElem(hasher.Sum(nil))
	miu := math.GaloisMul(c.nu, m)
	miu = math.GaloisMul(miu, math.HashQuadraticToGalois(r))
	miu = math.GaloisAdd(miu, rand)

	sigma := math.EllipticPow(t, c.nu)

	return Proof{
		miu:   miu,
		sigma: sigma,
		r:     r,
	}, nil
}

// VerifyProof validates if the given 'p' is exactly a sound
// proof against the given challenge 'c'
func VerifyProof(pp *PublicParams, c Chal, p Proof) bool {
	gamma := math.HashQuadraticToGalois(p.r)

	lhsParam := math.EllipticPow(p.sigma, gamma)
	lhs := math.BiLinearMap(lhsParam, math.GetGenerator())
	lhs = math.QuadraticMul(p.r, lhs)

	rhsParam := math.EllipticPow(math.HashToEllipticPt(c.idx), c.nu)
	rhsParam = math.EllipticPow(rhsParam, gamma)
	rhsParam = math.EllipticMul(rhsParam, math.EllipticPow(pp.u, p.miu))
	rhs := math.BiLinearMap(rhsParam, pp.v)

	return math.QuadraticEqual(lhs, rhs)
}

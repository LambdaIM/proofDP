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

package math

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	orderQValue = "8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791"
	orderRValue = "730750818665451621361119245571504901405976559617"

	// the radix of the literal numeric constants above
	radix = 10

	// size of a Byte in bits
	sizeOfByte = 8

	errInitFieldOrder       = "Failed to initialized the required Galois fields with order %s"
	errOperandsInDiffFields = "Arthimetic operation on elements from different fields"
)

// psuedo-constant, global
var (
	intZero = big.NewInt(0)
	intOne  = big.NewInt(1)
	intTwo  = big.NewInt(2)

	// there is NO struct constant in Go, therefore the global pointer
	// to Galois struct instances are employed as psuedo-constants
	gFQ *galF
	gFR *galF
)

// package level init(): initialize required Galois field instances
func initGalois() {
	gFQ = newGalF(orderQValue)
	gFR = newGalF(orderRValue)
}

type galF struct {
	ord *big.Int
	// quadratic non-residue
	qnr *big.Int
}

type galE struct {
	val *big.Int
	fld *galF
}

// TODO: restrict the newGalF() call
// newGalF() is a init() helper
func newGalF(ordV string) *galF {
	order, done := new(big.Int).SetString(ordV, radix)
	if !done {
		panic(fmt.Errorf(errInitFieldOrder, ordV))
	}

	// generate a random quadratic non-residue of the field
	for {
		qnrV, err := rand.Int(rand.Reader, order)
		if err != nil || qnrV.Cmp(intZero) == 0 {
			continue
		}

		if qnrV.ModSqrt(qnrV, order) != nil {
			return &galF{
				ord: order,
				qnr: qnrV,
			}
		}
	}
}

func newGalE(f *galF) *galE {
	return &galE{
		val: new(big.Int),
		fld: f,
	}
}

func randGalE(f *galF) (*galE, error) {
	rVal, err := rand.Int(rand.Reader, f.ord)

	if err != nil {
		return nil, err
	}

	return &galE{
		val: rVal,
		fld: f,
	}, nil
}

func newGalZero(f *galF) *galE {
	return &galE{
		val: big.NewInt(0),
		fld: f,
	}
}

func newGalOne(f *galF) *galE {
	return &galE{
		val: big.NewInt(1),
		fld: f,
	}
}

func (e *galE) set(a *galE) *galE {
	e.val.Set(a.val)
	e.fld = a.fld
	e.val.Mod(e.val, e.fld.ord)
	return e
}

func (e *galE) setV(v *big.Int) *galE {
	e.val.Mod(v, e.fld.ord)
	return e
}

func (e *galE) setVI(i int64) *galE {
	e.val.SetInt64(i)
	return e
}

// helper
func lenInByte(n *big.Int) int {
	return (n.BitLen() + sizeOfByte - 1) / sizeOfByte
}

// helper func to generate a big.Int from given hash
// for given hash data H, a generated value looks like:
// H || 0 || H || 1 || H || 2 || H ...
// if the constructed value v is larger than limit n, then
// calc the v' where v = 2*v' + r repeatedly, til v' < n
func valFromHash(hash []byte, limit *big.Int) *big.Int {
	hLen := len(hash)
	lLen := lenInByte(limit)
	buff := make([]byte, lLen)
	cpLen := 0
	count := uint8(0)

	for offset := 0; offset < lLen; {
		// H
		if lLen-offset < hLen {
			cpLen = lLen - offset
		} else {
			cpLen = hLen
		}
		copy(buff[offset:], hash[:cpLen])
		offset += cpLen
		if offset >= lLen {
			break
		}
		// count
		buff[offset] = byte(count)
		offset++
	}

	r := new(big.Int).SetBytes(buff)
	for limit.Cmp(r) < 0 {
		r.Quo(r, intTwo)
	}

	return r
}

func (e *galE) setHash(hash []byte) *galE {
	return e.setV(valFromHash(hash, e.fld.ord))
}

func (e *galE) setBytes(data []byte) *galE {
	return e.setV(new(big.Int).SetBytes(data))
}

func (e *galE) bytes() []byte {
	oLen := lenInByte(e.fld.ord)
	vBytes := e.val.Bytes()
	padding := make([]byte, oLen-len(vBytes))
	return append(padding, vBytes...)
}

func (e *galE) isSqr() bool {
	return big.Jacobi(e.val, e.fld.ord) == 1
}

func (e *galE) equal(a *galE) bool {
	return e.fld == a.fld && e.val.Cmp(a.val) == 0
}

func (e *galE) add(lhs, rhs *galE) *galE {
	if lhs.fld != rhs.fld {
		panic(errOperandsInDiffFields)
	}
	e.fld = lhs.fld
	return e.setV(new(big.Int).Add(lhs.val, rhs.val))
}

func (e *galE) sub(lhs, rhs *galE) *galE {
	if lhs.fld != rhs.fld {
		panic(errOperandsInDiffFields)
	}
	e.fld = lhs.fld
	return e.setV(new(big.Int).Sub(lhs.val, rhs.val))
}

func (e *galE) mul(lhs, rhs *galE) *galE {
	if lhs.fld != rhs.fld {
		panic(errOperandsInDiffFields)
	}
	e.fld = lhs.fld
	return e.setV(new(big.Int).Mul(lhs.val, rhs.val))
}

func (e *galE) mulI(lhs *galE, i int64) *galE {
	e.fld = lhs.fld
	return e.setV(new(big.Int).Mul(lhs.val, big.NewInt(i)))
}

func (e *galE) mulV(lhs *galE, v *big.Int) *galE {
	e.fld = lhs.fld
	return e.setV(new(big.Int).Mul(lhs.val, v))
}

func (e *galE) powI(lhs *galE, i int64) *galE {
	e.fld = lhs.fld
	return e.setV(new(big.Int).Exp(lhs.val, big.NewInt(i), lhs.fld.ord))
}

func (e *galE) powV(lhs *galE, v *big.Int) *galE {
	e.fld = lhs.fld
	return e.setV(new(big.Int).Exp(lhs.val, v, lhs.fld.ord))
}

func (e *galE) sqr(a *galE) *galE {
	return e.powI(a, 2)
}

func (e *galE) sqrt(a *galE) *galE {
	v := new(big.Int).ModSqrt(a.val, a.fld.ord)

	if v == nil {
		return nil
	}

	e.fld = a.fld
	return e.setV(v)
}

func (e *galE) inv(a *galE) *galE {
	e.fld = a.fld
	return e.setV(new(big.Int).ModInverse(a.val, a.fld.ord))
}

// sign() returns -1 for negative value;
// returns 0 for zero;
// returns +1 for positive value.
func (e *galE) sign() int {
	return e.val.Cmp(intZero)
}

func (e *galE) neg(a *galE) *galE {
	e.fld = a.fld

	if a.sign() == 0 {
		return e.setV(intZero)
	}

	return e.setV(new(big.Int).Sub(a.fld.ord, a.val))
}

func (e *galE) halve(a *galE) *galE {
	e.set(a)

	if e.val.Bit(0) == 1 {
		e.val.Add(e.val, e.fld.ord)
	}

	return e.setV(new(big.Int).Quo(e.val, intTwo))
}

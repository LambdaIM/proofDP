/*
 * Copyright (C) 2018 The Lambda Authors
 * This file is part of The Lambda library.
 *
 * The Lambda is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The Lambda is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The Lambda.  If not, see <http://www.gnu.org/licenses/>.
 */

package proofdp

import (
	"math/big"
	"math/rand"
)

// apply the constant seed for convenience
// FIXME: replace the constant random seed with a package init()
const (
	randSeed = 10001
)

// pseudo-constant, snake naming is employed for prompt purpose
var (
	bigInt0 = big.NewInt(0)
	bigInt1 = big.NewInt(1)
	bigInt2 = big.NewInt(2)
)

// global random source
var randSrc *rand.Rand

// the implementation of GF(p), also denoted as Z/pZ or simply Zp
type (
	// field structure
	zpField struct {
		order   *big.Int
		pairing *Pairing
		// non-residue, used only in quadratic field computation convenience
		nqr     *zpElem
	}

	// field element structure
	zpElem struct {
		v     *big.Int
		field *zpField
	}
)

// new instance
func newZpField(order *big.Int) *zpField {
	return &zpField{order, nil, nil }
}

func newZpElem(f *zpField) *zpElem {
	return &zpElem{new(big.Int), f }
}

func randomZpElem(f *zpField) *zpElem {
	if randSrc == nil {
		randSrc = rand.New(rand.NewSource(randSeed))
	}
	return &zpElem{new(big.Int).Rand(randSrc, f.order), f }
}

// new special instance, for convenience
func newZpZero(f *zpField) *zpElem {
	return &zpElem{big.NewInt(0), f }
}

func newZpOne(f *zpField) *zpElem {
	return &zpElem{big.NewInt(1), f }
}

// all arithmetic operations on Zp field will be implemented in the style
// of Go's official big.Int package
// WARNING: as inner methods, no pre-check required
// QUESTION: Should we provide public func here?
// -------------------- field methods ---------------------- //
// f == another
func (f *zpField) isSame(another *zpField) bool {
	return f.order.Cmp(another.order) == 0
}

// for arithmetic operations on
func (f *zpField) genNqr() *zpElem {
	for {
		f.nqr = randomZpElem(f)
		r := f.nqr.sqrt(f.nqr)
		if r != nil {
			break
		}
	}
	return f.nqr
}

func (f *zpField) getNqr() *zpElem {
	if f.nqr == nil {
		return f.genNqr()
	} else {
		return f.nqr
	}
}

// for test purpose
func (f *zpField) resetNqr(nqr *zpElem) *zpElem {
	if f.nqr == nil {
		f.nqr = nqr
	} else {
		f.nqr.set(nqr)
	}
	return f.nqr
}

// ------------------- element methods --------------------- //
// element assignment
func (e *zpElem) set(a *zpElem) *zpElem {
	e.v = new(big.Int).Mod(a.v, a.field.order)
	e.field = a.field
	return e
}

// value assignment, for convenience
func (e *zpElem) setV(v *big.Int) *zpElem {
	e.v.Mod(v, e.field.order)
	return e
}

func (e *zpElem) setVI(i int64) *zpElem {
	e.v.Mod(big.NewInt(i), e.field.order)
	return e
}

func (e *zpElem) setOne() *zpElem {
	e.v.SetInt64(1)
	return e
}

func (e *zpElem) setHash(hash []byte) *zpElem {
	e.setV(hashToBigInt(hash, e.field.order))
	return e
}

func (e *zpElem) setStr(s string, base int) (*zpElem, bool) {
	v, r := new(big.Int).SetString(s, base)
	if r {
		e.setV(v)
	}
	return e, r
}

func (e *zpElem) setBytes(buf []byte) *zpElem {
	e.setV(new(big.Int).SetBytes(buf))
	return e
}

func (e *zpElem) toStr() string {
	return e.v.String()
}

func countBytes(n *big.Int) int {
	// FIXME: remove the magic number
	return (n.BitLen() + 7) / 8
}

// convert e to toBytes
func (e *zpElem) toBytes() []byte {
	orderByteCount := countBytes(e.field.order)
	bytes := e.v.Bytes()
	padding := make([]byte, orderByteCount - len(bytes))
	return append(padding, bytes...)
}

// e == another
func (e *zpElem) equal(another *zpElem) bool {
	return e.field.isSame(another.field) &&
		e.v.Cmp(another.v) == 0
}

// WARNING: we assume that all arithmetic operands belongs to same field
// e = lhs + rhs, belongs to lhs.field
func (e *zpElem) add(lhs *zpElem, rhs *zpElem) *zpElem {
	v := new(big.Int).Add(lhs.v, rhs.v)
	e.setV(v)
	e.field = lhs.field
	return e
}

// e = lhs - rhs, belongs to lhs.field
func (e *zpElem) sub(lhs *zpElem, rhs *zpElem) *zpElem {
	v := new(big.Int).Sub(lhs.v, rhs.v)
	e.setV(v)
	e.field = lhs.field
	return e
}

// e = lhs * rhs, belongs to lhs.field
func (e *zpElem) mul(lhs *zpElem, rhs *zpElem) *zpElem {
	v := new(big.Int).Mul(lhs.v, rhs.v)
	e.setV(v)
	e.field = lhs.field
	return e
}

// e = lhs * i, belongs to lhs.field
func (e *zpElem) mulI(lhs *zpElem, i int64) *zpElem {
	v := new(big.Int).Mul(lhs.v, big.NewInt(i))
	e.setV(v)
	e.field = lhs.field
	return e
}

// e = lhs * n, belongs to lhs.field
func (e *zpElem) mulN(lhs *zpElem, n *big.Int) *zpElem {
	v := new(big.Int).Mul(lhs.v, n)
	e.setV(v)
	e.field = lhs.field
	return e
}

// e = a^n, belongs to a.field
func (e *zpElem) powN(a *zpElem, n *big.Int) *zpElem {
	e.v = new(big.Int).Exp(a.v, n, a.field.order)
	e.field = a.field
	return e
}

// e = a^i, belongs to a.field
func (e *zpElem) powI(a *zpElem, i int64) *zpElem {
	return e.powN(a, big.NewInt(i))
}

// e = a^b, belongs to a.field
func (e *zpElem) pow(a *zpElem, b *zpElem) *zpElem {
	return e.powN(a, b.v)
}

// e = a^2, belongs to a.field
func (e *zpElem) sqr(a *zpElem) *zpElem {
	return e.powI(a, 2)
}

// e = a^-1, belongs to a.field
func (e *zpElem) inv(a *zpElem) *zpElem {
	v := new(big.Int)
	v.ModInverse(a.v, a.field.order)
	e.setV(v)
	e.field = a.field
	return e
}

// e = a^(1/2), belongs to a.field
// WARNING: this method has similar output logic with big.Int.ModSqrt()
func (e *zpElem) sqrt(a *zpElem) *zpElem {
	v := new(big.Int).ModSqrt(a.v, a.field.order)
	if v == nil {
		return nil
	}
	e.setV(v)
	e.field = a.field
	return e
}

// e = -a, belongs to a.field
func (e *zpElem) neg(a *zpElem) *zpElem {
	// 0 case
	if big.NewInt(0).Cmp(a.v) == 0 {
		e.v.SetInt64(0)
		e.field = a.field
		return e
	}
	v := new(big.Int).Sub(a.field.order, a.v)
	e.setV(v)
	e.field = a.field
	return e
}

// e = 1/2 * a, belongs to a.field
func (e *zpElem) halve(a *zpElem) *zpElem {
	r := new(big.Int).Mod(a.v, bigInt2)
	v := new(big.Int).Set(a.v)
	// odd case
	if r.Cmp(bigInt0) != 0 {
		v.Add(v, a.field.order)
	}
	q := new(big.Int).Quo(v, bigInt2)
	e.setV(q)
	e.field = a.field
	return e
}

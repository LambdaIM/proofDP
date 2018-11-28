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
	"fmt"
	"math/big"
	"strings"
)

// the implmentation of qualdratic field
type (
	// field structure
	qdField struct {
		zp      *zpField
		order   *big.Int
		pairing *Pairing
	}

	// field element structure
	qdElem struct {
		x     *zpElem
		y     *zpElem
		field *qdField
	}
)

// new instance
func newQdField(field *zpField, pairing *Pairing) *qdField {
	order := new(big.Int).Mul(field.order, field.order)
	return &qdField{field, order, pairing }
}

func newQdElem(field *qdField) *qdElem {
	return &qdElem{newZpZero(field.zp), newZpZero(field.zp), field}
}

// ----------------------- field methods ------------------------ //
func (f *qdField) getNqr() *zpElem {
	return f.zp.getNqr()
}

// for test purpose
func (f *qdField) resetNqr(nqr *zpElem) *zpElem {
	return f.zp.resetNqr(nqr)
}

func (f *qdField) isSame(another *qdField) bool {
	return f.order.Cmp(another.order) == 0
}

// ---------------------- element methods ----------------------- //
// e = another, assignment
func (e *qdElem) set(another *qdElem) *qdElem {
	e.x.set(another.x)
	e.y.set(another.y)
	e.field = another.field
	return e
}

func (e *qdElem) setIdentity() *qdElem {
	e.x.setVI(1)
	e.y.setVI(0)
	return e
}

// value string looks like: [x,y]
func (e *qdElem) setStr(s string, base int) (*qdElem, bool) {
	r := false
	t := strings.TrimSpace(s)
	// basic format check
	// TODO: really necessary here?
	if strings.Index(t, "[") == 0 &&
		strings.LastIndex(t, "]") == len(t) - 1 {
		split := strings.Split(strings.Trim(t, "[]"), ",")
		_, r = e.x.setStr(strings.TrimSpace(split[0]), base)
		if r {
			_, r = e.y.setStr(strings.TrimSpace(split[1]), base)
		}
	}
	if !r {
		e.set(newQdElem(e.field))
	}
	return e, r
}

func (e *qdElem) setBytes(buf []byte) *qdElem {
	zpLen := len(buf) / 2
	e.x.setBytes(buf[: zpLen])
	e.y.setBytes(buf[zpLen :])
	return e
}

func (e *qdElem) toStr() string {
	return fmt.Sprintf("[%s,%s]", e.x.toStr(), e.y.toStr())
}

// convert e to toBytes
func (e *qdElem) toBytes() []byte {
	return append(e.x.toBytes(), e.y.toBytes()...)
}

// WARNING: we assume that all arithmetic operands belongs to same field
func (e *qdElem) equal(another *qdElem) bool {
	return e.field.isSame(another.field) &&
		e.x.equal(another.x) &&
		e.y.equal(another.y)
}

// e = another^-1, belongs to another.field
// fi invert implementation
func (e *qdElem) inv(another *qdElem) *qdElem {
	e0 := newZpElem(another.field.zp).sqr(another.x)
	e1 := newZpElem(another.field.zp).sqr(another.y)
	e0.add(e0, e1)
	e0.inv(e0)
	e.x = newZpElem(another.field.zp).mul(another.x, e0)
	e0.neg(e0)
	e.y = newZpElem(another.field.zp).mul(another.y, e0)
	e.field = another.field
	return e
}

// e = lhs * rhs, belongs to lhs.field
// fi multiplication implementation
func (e *qdElem) mul(lhs *qdElem, rhs *qdElem) *qdElem {
	// Karatsuba
	e0 := newZpElem(lhs.field.zp).add(lhs.x, lhs.y)
	e1 := newZpElem(lhs.field.zp).add(rhs.x, rhs.y)
	e2 := newZpElem(lhs.field.zp).mul(e0, e1)
	e0.mul(lhs.x, rhs.x)
	e2.sub(e2, e0)
	e1.mul(lhs.y, rhs.y)
	e.x.sub(e0, e1)
	e.y.sub(e2, e1)
	// field
	e.field = lhs.field
	return e
}

// e = another^2, belongs to another.field
// fi square implementation
func (e *qdElem) sqr(another *qdElem) *qdElem {
	// Re(n) = x^2 - y^2 = (x+y)(x-y)
	e0 := newZpElem(another.field.zp).add(another.x, another.y)
	e1 := newZpElem(another.field.zp).sub(another.x, another.y)
	e0.mul(e0, e1)
	// Im(n) = 2xy
	e1.mul(another.x, another.y)
	e1.add(e1, e1)
	e.x.set(e0)
	e.y.set(e1)
	// field
	e.field = another.field
	return e
}

// e = a^n, belongs to a.field
func (e *qdElem) powN(a *qdElem, n *big.Int) *qdElem {
	exp := new(big.Int).Set(n)
	tmp := newQdElem(a.field).set(a)
	res := newQdElem(a.field).setIdentity()
	for exp.Cmp(bigInt0) > 0 {
		// check least digit bit, note that bit.Int.Bit() returns in little-endian form
		if exp.Bit(0) != 0 {
			res.mul(res, tmp)
		}
		tmp.sqr(tmp)
		exp.Quo(exp, bigInt2)
	}
	e.set(res)
	return e
}

// ----------------- field related calculation --------------------- //
// lucasOdd sequence
// set the calculation result to out, which belongs to in.field
// WARNING: out/in content will change
// WARNING: Requires cofac to be odd
func lucasOdd(out *qdElem, in *qdElem, tmp *qdElem, cofac *big.Int) {
	// setup
	tmp.x.setVI(2)
	tmp.y.add(in.x, in.x)
	out.set(tmp)
	// calculate power
	for offset := cofac.BitLen() - 1; ; offset-- {
		if offset == 0 {
			out.y.mul(out.x, out.y)
			out.y.sub(out.y, tmp.y)
			out.x.sqr(out.x)
			out.x.sub(out.x, tmp.x)
			break
		}
		if cofac.Bit(offset) == 1 {
			out.x.mul(out.x, out.y)
			out.x.sub(out.x, tmp.y)
			out.y.sqr(out.y)
			out.y.sub(out.y, tmp.x)
		} else {
			out.y.mul(out.x, out.y)
			out.y.sub(out.y, tmp.y)
			out.x.sqr(out.x)
			out.x.sub(out.x, tmp.x)
		}
	}
	// assume cofactor = (q+1)/r is even (r should be odd and q+1 is always even)
	// thus v0 = V_{k}, v1 = V_{k+1} and V_{k-1} = P v0 - v1
	// so U_k = (P V_{k} - 2 V_{k-1}) / (P^2 - 4) = (2 v1 - P v0) / (P^2 - 4)
	in.x.mul(out.x, tmp.y)
	out.y.add(out.y, out.y)
	out.y.sub(out.y, in.x)
	tmp.y.sqr(tmp.y)
	tmp.y.sub(tmp.y, tmp.x)
	tmp.y.sub(tmp.y, tmp.x)
	tmp.y.inv(tmp.y)
	out.y.mul(out.y, tmp.y)
	out.x.halve(out.x)
	out.y.mul(out.y, in.y)
}

// type A pairing calculation
// set the calculation result to out, which belongs to in.field
// WARNING: out/in content will change
func tateexp(out *qdElem, in *qdElem, tmp *qdElem, cofac *big.Int) {
	// calculate exponent by q-1
	tmp.inv(in)
	in.y.neg(in.y)
	in.mul(in, tmp)
	// calculate exponent by (q+1)/r
	// apply Lucas sequence(see "Compressed Pairings", Scott & Barreto)
	// instead of out.powN(in, cofactor)
	lucasOdd(out, in, tmp, cofac)
}


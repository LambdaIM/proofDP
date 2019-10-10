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
	"math/big"
)

type quadE struct {
	x *galE
	y *galE
}

func newQuadE() *quadE {
	return &quadE{
		x: newGalZero(gFQ),
		y: newGalZero(gFQ),
	}
}

func (e *quadE) set(a *quadE) *quadE {
	e.x.set(a.x)
	e.y.set(a.y)
	return e
}

func (e *quadE) setIdentity() *quadE {
	e.x.setVI(1)
	e.y.setVI(0)
	return e
}

func (e *quadE) bytes() []byte {
	return append(e.x.bytes(), e.y.bytes()...)
}

func (e *quadE) setBytes(data []byte) *quadE {
	l := len(data) / 2
	e.x.setBytes(data[:l])
	e.y.setBytes(data[l:])
	return e
}

func (e *quadE) equal(a *quadE) bool {
	return e.x.equal(a.x) && e.y.equal(a.y)
}

func (e *quadE) inv(a *quadE) *quadE {
	// m = 1/(a.x^2 + a.y^2)
	m := newGalE(gFQ).sqr(a.x)
	n := newGalE(gFQ).sqr(a.y)
	m.add(m, n)
	m.inv(m)
	// e.x = a.x * m, e.y = -a.y * m
	e.x = newGalE(gFQ).mul(a.x, m)
	m.neg(m)
	e.y = newGalE(gFQ).mul(a.y, m)
	return e
}

func (e *quadE) mul(lhs, rhs *quadE) *quadE {
	// Karatsuba
	m := newGalE(gFQ).add(lhs.x, lhs.y)
	n := newGalE(gFQ).add(rhs.x, rhs.y)
	k := newGalE(gFQ).mul(m, n) // (lhs.x + lhs.y)(rhs.x  + rhs.y)
	m.mul(lhs.x, rhs.x)
	k.sub(k, m)         // (lhs.x + lhs.y)(rhs.x + rhs.y) - lhs.x * rhs.x
	n.mul(lhs.y, rhs.y) // lhs.y * rhs.y
	e.x.sub(m, n)       // lhs.x * rhs.x - lhs.y * rhs.y
	e.y.sub(k, n)       // lhs.x * rhs.y + lhs.y * rhs.x
	return e
}

func (e *quadE) sqr(a *quadE) *quadE {
	// Re(e) = x^2 - y^2
	m := newGalE(gFQ).add(a.x, a.y)
	n := newGalE(gFQ).sub(a.x, a.y)
	m.mul(m, n)
	// Im(e) = 2 * x * y
	n.mul(a.x, a.y)
	n.add(n, n)
	e.x.set(m)
	e.y.set(n)
	return e
}

func (e *quadE) powN(a *quadE, n *big.Int) *quadE {
	exp := new(big.Int).Set(n)
	tmp := newQuadE().set(a)
	res := newQuadE().setIdentity()
	for exp.Cmp(intZero) > 0 {
		if exp.Bit(0) == 1 {
			res.mul(res, tmp)
		}
		tmp.sqr(tmp)
		exp.Quo(exp, intTwo)
	}
	return e.set(res)
}

// a pairing calc mainly in the quadratic field
// WARNING: out/in/tmp content will change
func calcTateExp(out, in, tmp *quadE, cofac *big.Int) {
	// calculate exponent by q-1
	tmp.inv(in)
	in.y.neg(in.y)
	in.mul(in, tmp)
	// calc expo by (q + 1)/r using Lucas sequence
	calcLucasSeq(out, in, tmp, cofac)
}

// WARNING: out/in/tmp content will change
func calcLucasSeq(out, in, tmp *quadE, cofac *big.Int) {
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

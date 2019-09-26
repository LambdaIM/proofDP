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
	"encoding/base64"
	"fmt"
	"math/big"
)

// implement an elliptic curve y^2 = x^3 + x on Galois field 'gFQ'
const (
	genValue   = "bKiQ2I+udgyl7aDwDARsdtPaZeKPRtsNB3ch7BflAYyZ7q/54XPs9kAcueh2b7YRF8Qhm66Zpjt5y8AvQq9/XWXbh+10uNqhPxzxw3QA9CpAQttozpvHRcyUqJZN4YxpyImd54SDchgYS5u47AMMw8JGj55rqkCWEIHSXs+cLig="
	coFacValue = "12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776"

	// panic info
	errInitCurveParamFmt   = "Failed to initalized the required elliptic curve parameters: %s"
	errInitCurveProperties = "Failed to initalized the key parameters of the elliptic curve"
	errInvalidCurvePoint   = "Failed to locate point on elliptic curve"
)

// psuedo-constant
var (
	gen   *curP
	coFac *big.Int
)

// package level init(): initialize the co-factor constant
func initElliptic() {
	genData, err := base64.StdEncoding.DecodeString(genValue)
	if err != nil {
		panic(fmt.Errorf(errInitCurveParamFmt, err.Error()))
	}
	gen = newCurP().setBytes(genData)
	if !validateCurP(gen) {
		panic(errInitCurveProperties)
	}
	var done bool
	coFac, done = new(big.Int).SetString(coFacValue, radix)
	if !done {
		panic(fmt.Errorf(errInitCurveParamFmt, "Cannot load cofactor"))
	}
}

type curP struct {
	inf bool
	x   *galE
	y   *galE
}

func newCurP() *curP {
	return &curP{
		inf: true,
		x:   newGalZero(gFQ),
		y:   newGalZero(gFQ),
	}
}

// for test purpose only, restrict function call
func randCurP() (*curP, error) {
	n, err := rand.Int(rand.Reader, gFQ.ord)
	if err != nil {
		return nil, err
	}
	return newCurP().powN(gen, n), nil
}

// a semantic wrap
func newCurIdentity() *curP {
	return newCurP()
}

func dupCurP(p *curP) *curP {
	return &curP{
		inf: p.inf,
		x:   newGalE(gFQ).set(p.x),
		y:   newGalE(gFQ).set(p.y),
	}
}

func (p *curP) set(a *curP) *curP {
	p.inf = a.inf
	if !p.inf {
		p.x.set(a.x)
		p.y.set(a.y)
	}
	return p
}

func (p *curP) setHash(hash []byte) *curP {
	p.inf = false
	p.x.setHash(hash)

	for {
		y := newGalE(gFQ).powI(p.x, 3)
		y.add(y, p.x)

		if y.isSqr() {
			p.y.sqrt(y)
			break
		}

		p.x.sqr(p.x)
		p.x.add(p.x, newGalOne(gFQ))
	}

	if p.y.sign() < 0 {
		p.y.neg(p.y)
	}

	return p.powN(p, coFac)
}

func validateCurP(p *curP) bool {
	if p.inf {
		return true
	}
	// check the equation:
	// p.y^2 = p.x^3 + p.x
	lhs := newGalE(gFQ).powI(p.x, 3)
	lhs.add(lhs, p.x)
	rhs := newGalE(gFQ).sqr(p.y)
	return lhs.equal(rhs)
}

// for test purpose only
func (p *curP) setBytes(data []byte) *curP {
	p.inf = false
	l := len(data) / 2
	p.x.setBytes(data[:l])
	p.y.setBytes(data[l:])
	if !validateCurP(p) {
		panic(errInvalidCurvePoint)
	}
	return p
}

// for test purpose only
func (p *curP) bytes() []byte {
	if p.inf {
		return []byte{}
	}
	return append(p.x.bytes(), p.y.bytes()...)
}

// double calc for non-infinity | on-x-axis point
func (p *curP) doubleNormal(a *curP) *curP {
	r := newCurP()
	r.inf = false
	// calc m = (3 * a.x^2 + 1)/(2 * a.y)
	m := newGalE(gFQ).sqr(a.x)
	m.mulI(m, 3)
	m.add(m, newGalOne(gFQ))
	t := newGalE(gFQ).mulI(a.y, 2)
	m.mul(m, t.inv(t))
	// r.x = m^2 - 2 * a.x
	n := newGalE(gFQ).sqr(m)
	t.mulI(a.x, 2)
	r.x.sub(n, t)
	// r.y = (a.x - r.x) * m - a.y
	n.sub(a.x, r.x)
	r.y.mul(n, m)
	r.y.sub(r.y, a.y)
	return p.set(r)
}

func (p *curP) double(a *curP) *curP {
	// infinity | on-x-axis
	if a.inf || a.y.val.Cmp(intZero) == 0 {
		p.inf = true
		return p
	}
	return p.doubleNormal(a)
}

func (p *curP) add(lhs, rhs *curP) *curP {
	// one of the operands is infinity point
	if lhs.inf {
		p.set(rhs)
		return p
	}
	if rhs.inf {
		p.set(lhs)
		return p
	}

	// lhs.x == rhs.x
	if lhs.x.equal(rhs.x) {
		// lhs.y == rhs.y
		if lhs.y.equal(rhs.y) {
			// lhs.y == rhs.y == 0 -> the sum is infinity
			if lhs.y.val.Cmp(intZero) == 0 {
				p.inf = true
				return p
			}
			// lhs, rhs is the same point
			return p.doubleNormal(lhs)
		}
		// lhs.y == -(rhs.y) -> the sum is infinity
		p.inf = true
		return p
	}

	// calc s = (rhs.y - lhs.y)/(rhs.x - lhs.x)
	s := newGalE(gFQ).sub(rhs.y, lhs.y)
	t := newGalE(gFQ).sub(rhs.x, lhs.x)
	t.inv(t)
	s.mul(s, t)
	// t = s^2 - lhs.x - rhs.x
	t.sqr(s)
	t.sub(t, lhs.x)
	t.sub(t, rhs.x)
	// r = (lhs.x - t) * s - lhs.y
	r := newGalE(gFQ).sub(lhs.x, t)
	r.mul(r, s)
	r.sub(r, lhs.y)

	p.inf = false
	p.x.set(t)
	p.y.set(r)
	return p
}

func (p *curP) mul(lhs, rhs *curP) *curP {
	return p.add(lhs, rhs)
}

func (p *curP) sqr(a *curP) *curP {
	return p.double(a)
}

// TODO: optimize this
func (p *curP) powN(a *curP, n *big.Int) *curP {
	exp := new(big.Int).Set(n)
	tmp := newCurP().set(a)
	res := newCurIdentity()
	for exp.Cmp(intZero) > 0 {
		if exp.Bit(0) != 0 {
			res.mul(res, tmp)
		}
		tmp.sqr(tmp)
		exp.Quo(exp, intTwo)
	}
	return p.set(res)
}

// NOTE: neg() here is actually find the point that is
// x-axis symmetrical to input 'a' point
func (p *curP) neg(a *curP) *curP {
	if !a.inf {
		p.inf = false
		p.x.set(a.x)
		p.y.neg(a.y)
	}
	return p
}

func (p *curP) equal(a *curP) bool {
	if p.inf && a.inf {
		return true
	}
	if !p.inf && !a.inf {
		return p.x.equal(a.x) && p.y.equal(a.y)
	}
	return false
}

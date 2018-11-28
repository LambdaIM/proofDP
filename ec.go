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

// the implementation of elliptic curve on certain Z/pZ field
type (
	// elliptic curve structure
	eCurve struct {
		a          *zpElem
		b          *zpElem // x^3 + a*x + b
		cofac      *big.Int
		genNoCofac *ecPoint
		gen        *ecPoint
		zp         *zpField
	}

	// structure of elliptic curve point
	ecPoint struct {
		inf   bool // infinity flag
		x     *zpElem
		y     *zpElem
		curve *eCurve
	}
)

func isValidOnCurve(p *ecPoint) bool {
	if p.inf {
		return true
	}
	c := p.curve
	lhs := newZpElem(c.zp).sqr(p.x)
	lhs.add(lhs, c.a)
	lhs.mul(lhs, p.x)
	lhs.add(lhs, c.b) // (x^2 + a)x + b
	rhs := newZpElem(c.zp).sqr(p.y) // y^2
	return rhs.equal(lhs)
}

// new instance
func newEcPoint(c *eCurve) *ecPoint {
	// a point at infinity
	return &ecPoint{true, newZpZero(c.zp),newZpZero(c.zp), c }
}

// pick a identity from given curve
func newEcIdentity(c *eCurve) *ecPoint {
	return newEcPoint(c)
}

// pick a pseudo-random point from given curve as generator seed of curve
func genGeneratorNoCofactor(c *eCurve) *ecPoint {
	// TODO: add valid algorithm to create a negate y with 0.5 probability
	r := newEcPoint(c)
	r.inf = false
	// pick a point whose y component is a complete square number
	for {
		x := randomZpElem(c.zp)
		y := newZpElem(c.zp).sqr(x)
		y.add(y, c.a)
		y.mul(y, x)
		y.add(y, c.b) // (x^2 + a) * x + b
		rt := y.sqrt(y)
		if rt != nil {
			r.x.set(x)
			r.y.set(y)
			break
		}
	}
	return r
}

func newEcCurve(zp *zpField, a *zpElem, b *zpElem, cofac *big.Int) *eCurve {
	curve := new(eCurve)
	curve.zp = zp
	curve.a = a
	curve.b = b
	curve.cofac = cofac
	curve.genNoCofac = genGeneratorNoCofactor(curve)
	curve.gen = newEcPoint(curve).powN(curve.genNoCofac, curve.cofac)
	return curve
}

func randomEcPoint(c *eCurve) *ecPoint {
	n := randomZpElem(c.zp)
	r := newEcPoint(c)
	return r.powN(c.gen, n.v)
}

func duplicateEcPoint(p *ecPoint) *ecPoint {
	return newEcPoint(p.curve).set(p)
}

// ----------------------- curve methods ------------------------- //
func (c *eCurve) newGenerator() *ecPoint {
	gen := newEcPoint(c)
	gen.powN(c.genNoCofac, c.cofac)
	return gen
}

// for test purpose
func (c *eCurve) resetCurveGenerator(genNoCofac *ecPoint, cofac *big.Int) *eCurve {
	if cofac != nil {
		c.cofac = cofac
	}
	c.genNoCofac.set(genNoCofac)
	c.gen.powN(c.genNoCofac, c.cofac)
	return c
}

// ----------------------- point methods ------------------------- //
func (p *ecPoint) zpField() *zpField {
	return p.curve.zp
}

// p = another
func (p *ecPoint) set(another *ecPoint) *ecPoint {
	// infinity case
	if another.inf {
		p.inf = true
		return p
	}
	// finite case
	p.inf = false
	p.x.set(another.x)
	p.y.set(another.y)
	p.curve = another.curve
	return p
}

// generate a big.Int instance from given hash value v
// for short hash data H, we create a byte buff looks like:
// H || 0 || H || 1 || H || ...
// if the constructed value v is larger than limit n, then
// calculate the v' where v = 2*v' + r repeatedly, until v' < n
func hashToBigInt(hash []byte, limit *big.Int) *big.Int {
	hashLen := len(hash)
	totalLen := countBytes(limit)
	rBytes := make([]byte, totalLen)
	cpLen := 0
	count := uint8(0)
	for offset := 0; offset < totalLen; {
		// H
		if totalLen - offset < hashLen {
			cpLen = totalLen - offset
		} else {
			cpLen = hashLen
		}
		copy(rBytes[offset :], hash[: cpLen])
		offset += cpLen
		if offset >= totalLen { break }
		// count
		rBytes[offset] = byte(count)
		offset++
	}
	r := new(big.Int).SetBytes(rBytes)
	for ; limit.Cmp(r) < 0; {
		r.Quo(r, bigInt2)
	}
	return r
}

// set ecPoint to the one generated from given hash
func (p *ecPoint) setHash(hash []byte) *ecPoint {
	p.inf = false
	p.x.setV(hashToBigInt(hash, p.curve.zp.order))
	for {
		y := newZpElem(p.curve.zp)
		y.powI(p.x, 2)
		y.add(y, p.curve.a)
		y.mul(y, p.x)
		y.add(y, p.curve.b) // y = (x^2 + a) * x + b
		r := y.sqrt(y)
		if r != nil {
			p.y.set(y)
			break
		} else {
			p.x.sqr(p.x)
			p.x.add(p.x, newZpOne(p.curve.zp)) // x = x^2 + 1
		}
	}
	p.powN(p, p.curve.cofac)
	return p
}

// non-infinity value string looks like: [x,y]
// the infinity point string is just "0"
func (p *ecPoint) setStr(s string, base int) (*ecPoint, bool) {
	r := false
	t := strings.TrimSpace(s)
	// non-infinity point check
	if strings.Compare(t, "0") == 0 {
		// basic format check
		// TODO: really necessary?
		if strings.Index(t, "[") == 0 &&
			strings.LastIndex(t, "]") == len(t) - 1 {
			split := strings.Split(strings.Trim(t, "[]"), ",")
			_, r = p.x.setStr(strings.TrimSpace(split[0]), base)
			if r {
				_, r = p.y.setStr(strings.TrimSpace(split[1]), base)
			}
		}
	}
	if !r || !isValidOnCurve(p) {
		p.set(newEcPoint(p.curve))
	}
	return p, r
}

func (p *ecPoint) setBytes(buf []byte) *ecPoint {
	p.inf = false
	zpLen := len(buf) / 2
	p.x.setBytes(buf[: zpLen])
	p.y.setBytes(buf[zpLen :])
	if !isValidOnCurve(p) {
		p.set(newEcPoint(p.curve))
	}
	return p
}

func (p *ecPoint) toStr() string {
	if p.inf {
		return "0"
	}
	return fmt.Sprintf("[%s,%s]", p.x.toStr(), p.y.toStr())
}

func (p *ecPoint) toBytes() []byte {
	return append(p.x.toBytes(), p.y.toBytes()...)
}

// p = 2 * another, on another.curve, main procedure implementation
func (p *ecPoint) doubleInternal(another *ecPoint) *ecPoint {
	t := newEcPoint(another.curve)
	t.inf = false
	// local
	i := newZpElem(another.zpField())
	j := newZpElem(another.zpField())
	k := newZpElem(another.zpField())
	// i = (3 * another.x^2 + another.curve.a) / 2*another.y
	i.sqr(another.x)
	i.mulI(i, 3)
	i.add(i, another.curve.a) // 3 * another.x^2 + another.curve.a
	j.mulI(another.y, 2)
	j.inv(j) // 1 / (2 * another.y)
	i.mul(i, j)
	// t.x = i^2 - 2 * another.x
	k.sqr(i)
	j.mulI(another.x, 2)
	t.x.sub(k, j)
	// t.y = (another.x - t.x) * i - another.y
	k.sub(another.x, t.x)
	t.y.mul(k, i)
	t.y.sub(t.y, another.y)
	// set p to t
	p.set(t)
	return p
}

// WARNING: we assume that all the arithmetic operands locates on the same curve
// p = lhs + rhs, on lhs.curve
func (p *ecPoint) add(lhs *ecPoint, rhs *ecPoint) *ecPoint {
	// infinity point case
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
			if lhs.y.v.Cmp(bigInt0) == 0 {
				p.inf = true
				p.curve = lhs.curve
				return p
			} else {
				p.doubleInternal(lhs)
				return p
			}
		}
		// lhs and rhs are inverse to each other
		p.inf = true
		p.curve = lhs.curve
		return p
	}
	// otherwise
	e := newZpElem(p.curve.zp)
	e0 := newZpElem(p.curve.zp)
	e1 := newZpElem(p.curve.zp)
	// e = (rhs.y - lhs.y)/(rhs.x - lhs.x)
	e.sub(rhs.y, lhs.y)
	e0.sub(rhs.x, lhs.x)
	e0.inv(e0)
	e.mul(e, e0)
	// e0 = e^2 - lhs.x - rhs.x
	e0.sqr(e)
	e0.sub(e0, lhs.x)
	e0.sub(e0, rhs.x)
	// e1 = (lhs.x - e0) * e - lhs.y
	e1.sub(lhs.x, e0)
	e1.mul(e1, e)
	e1.sub(e1, lhs.y)
	// set p to t
	p.inf = false
	p.curve = lhs.curve
	p.x.set(e0)
	p.y.set(e1)
	return p
}

// p = lhs * rhs, on lhs.curve
func (p *ecPoint) mul(lhs *ecPoint, rhs *ecPoint) *ecPoint {
	return p.add(lhs, rhs)
}

// p = 2 * another, on another's curve
func (p *ecPoint) double(another *ecPoint) *ecPoint {
	// infinite point case
	if another.inf || another.y.v.Cmp(bigInt0) == 0 {
		p.inf = true
		p.curve = another.curve
		return p
	}
	// otherwise
	return p.doubleInternal(another)
}

// p = another^2, on another's curve
func (p *ecPoint) sqr(another *ecPoint) *ecPoint {
	return p.double(another)
}

// p = another^n, on another's curve
func (p *ecPoint) powN(another *ecPoint, n *big.Int) *ecPoint {
	exp := new(big.Int).Set(n)
	tmp := newEcPoint(another.curve).set(another)
	res := newEcIdentity(another.curve)
	for exp.Cmp(bigInt0) > 0 {
		// check least digit bit, note that bit.Int.Bit() returns in little-endian form
		if exp.Bit(0) != 0 {
			res.mul(res, tmp)
		}
		tmp.sqr(tmp)
		exp.Quo(exp, bigInt2)
	}
	p.set(res)
	return p
}

// p = -another, on another's curve
func (p *ecPoint) neg(another *ecPoint) *ecPoint {
	p.set(newEcPoint(another.curve))
	if !another.inf {
		p.inf = false
		p.x.set(another.x)
		p.y.neg(another.y)
	}
	return p
}

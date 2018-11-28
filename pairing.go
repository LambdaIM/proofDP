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
	"crypto/sha256"
	"math/big"
)

// the implmentation of pairing concept
type (
	// the pairing structure
	Pairing struct {
		r       *big.Int
		zr      *zpField
		g1      *eCurve
		g2      *eCurve
		gt      *GTField
		phikonr *big.Int
		data    *PairingData
	}

	// appended data for pairing structure
	// for convenience
	PairingData struct {
		fq    *zpField
		fq2   *qdField
		eq    *eCurve
		exp2  int
		exp1  int
		sign1 int
	}
)

// method to generate a pairing struct with given A-type param
func GenPairingWithAParam(param *AParam) *Pairing {
	// create instance
	res := new(Pairing)
	data := new(PairingData)
	res.data = data
	// scalar assignment
	data.sign1 = param.sign1
	data.exp2 = param.exp2
	data.exp1 = param.exp1
	res.r = param.r // order
	res.phikonr = param.h
	// zr field initialization
	res.zr = newZpField(param.r)
	res.zr.pairing = res
	// fq field initialization
	data.fq = newZpField(param.q)
	data.fq.pairing = res
	// eq field initialization
	data.eq = newEcCurve(data.fq, newZpOne(data.fq), newZpZero(data.fq), param.h)
	res.g1 = data.eq
	res.g2 = data.eq
	// fq2 field initialization
	data.fq2 = newQdField(data.fq, res)
	// pairing.gt field initialization
	res.gt = initPairingGT(res, data.fq2)
	return res
}

// ------------------- pairing method ----------------------- //
// calculate the e(u,v) of pairing
func (p *Pairing) E(u *ecPoint, v *ecPoint) *qdElem {
	r := newGTElem(p.gt)
	i1 := duplicateEcPoint(u)
	i2 := duplicateEcPoint(v)
	pairingElems(r, i1, i2)
	return r
}

func (p *Pairing) mapDataToZr(data []byte) *zpElem {
	v := new(big.Int).SetBytes(data)
	e := newZpElem(p.zr)
	e.setV(v)
	return e
}

// helper func
func dataSha256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// map binary data to certain elliptic curve point
func (p *Pairing) mapDataToG1(data []byte) *ecPoint {
	r := newEcPoint(p.g1)
	r.setHash(dataSha256(data))
	return r
}

func (p *Pairing) mapGTElemToZr(GTElem *qdElem) *zpElem {
	r := newZpElem(p.zr)
	r.setHash(dataSha256(GTElem.toBytes()))
	return r
}

// ------------------- pairing related operations --------------------- //
// WARNING: the following routines will change input parameters' content
// convert V from weighted projective (Jocobian) to affine
// i.euv. (X, Y, Z) --> (X / Z^2, Y / Z^3)
// also set z & z^2 to 1
func pointToAffine(e0 *zpElem, vx *zpElem, vy *zpElem, z *zpElem, z2 *zpElem) {
	z.inv(z)
	e0.sqr(z)
	vx.mul(vx, e0) // X / Z^2
	e0.mul(e0, z)
	vy.mul(vy, e0) // Y / Z^3
	z.setOne()
	z2.setOne()
}

func projDouble(e0 *zpElem, e1 *zpElem, e2 *zpElem, e3 *zpElem, vx *zpElem, vy *zpElem, z *zpElem, z2 *zpElem) {
	// 3x^2 + z^4
	e0.sqr(vx)     // e0 = x^2
	e1.add(e0, e0)     // e1 = 2x^2
	e0.add(e1, e0) // e0 = 3x^2
	e1.sqr(z2)     // e1 = z2^2
	e0.add(e0, e1) // e0 = 3x^2 + z2^2
	// z = 2yz'
	z.mul(vy, z) // z = yz'
	z.mulI(z, 2) // z = 2yz'
	// z^2
	z2.sqr(z) // z2 = z^2
	// 4xy^2
	e2.sqr(vy)
	e1.mul(vx, e2) // xy^2
	e1.mulI(e1, 4)
	// x = e0^2 - 2e1
	e3.mulI(e1, 2)
	vx.sqr(e0)
	vx.sub(vx, e3)
	// 8y^4
	e2.sqr(e2)
	e2.mulI(e2, 8)
	// y = e0(e1 - x) - e2
	e1.sub(e1, vx)
	e0.mul(e0, e1)
	vy.sub(e0, e2)
}

// a = -(3x^2 + cca z^4)
// for this case cca = 1
// b = 2 y z^3
// c = -(2 y^2 + x a)
// a = z^2 a
// here we take e1 = a, e2 = b, e3 = c
func computeABCTangentProj(e0 *zpElem, e1 *zpElem, e2 *zpElem, e3 *zpElem,
	vx *zpElem, vy *zpElem,
	z *zpElem, z2 *zpElem) {
	// e1 = -(3x^2 + z^4)
	e1.sqr(z2)     // z2^2
	e2.sqr(vx)     // x^2
	e0.mulI(e2, 2) // 2x^2
	e2.add(e0, e2) // 3x^2
	e1.add(e1, e2) // 3x^2 + z2^2
	e1.neg(e1)
	// e2 = 2yz^3
	e0.mulI(vy, 2) // 2y
	e2.mul(e0, z2) // 2yz^2
	e2.mul(e2, z)  // 2yz^3
	// e3 = -(2y^2 + e1*x)
	e3.mul(vx, e1) // a'x
	// e1 = e1*z^2, interrupted, since a will change
	e1.mul(e1, z2) // a'z2
	// e3 = -(2y^2 + e1*'x)
	e0.mul(e0, vy) // 2y^2
	e3.add(e3, e0) // 2y^2 + a'x
	e3.neg(e3)
}

// computes a Qx + b Qy + c for type A pairing
// a = e1, b = e2, c = e3
func millerEvalFn(f0 *qdElem, e1 *zpElem, e2 *zpElem, e3 *zpElem, qx *zpElem, qy *zpElem) {
	// map Q(x, y) via (x, y) --> (-x, iy)
	// hence, Re(aqx + bqy + c) = -aqx' + c and Im(aqx + bqy +c) = bqy'
	f0.y.mul(e1, qx) // aqx'
	f0.x.sub(e3, f0.y) // c - aqx'
	f0.y.mul(e2, qy) // bqy'
}

// a = e1, b = e2, c = e3
func computeABCLine(e0 *zpElem, e1 *zpElem, e2 *zpElem, e3 *zpElem, vx *zpElem, vy *zpElem, v1x *zpElem, v1y *zpElem) {
	// a = -(B.y - A.y) / (B.x - A.x)
	// b = 1
	// c = -(A.y + a * A.x)
	// after simplification:
	// a = -(B.y - A.y)
	e1.sub(vy, v1y) // A.y - B.y
	// b = B.x - A.x
	e2.sub(v1x, vx) // B.x - A.x
	// c = -(b * A.y + a * A.x)
	e3.mul(vx, v1y) // A.x * B.y
	e0.mul(vy, v1x) // A.y * B.x
	e3.sub(e3, e0) // B.x * A.y - A.x * B.y
}

func doTangent(e0 *zpElem, e1 *zpElem, e2 *zpElem, e3 *zpElem,
	vx *zpElem, vy *zpElem,
	qx *zpElem, qy *zpElem,
	z *zpElem, z2 *zpElem,
	f *qdElem, f0 *qdElem) {
	computeABCTangentProj(e0, e1, e2, e3, vx, vy, z, z2)
	millerEvalFn(f0, e1, e2, e3, qx, qy)
	f.mul(f, f0)
}

func doLine(e0 *zpElem, e1 *zpElem, e2 *zpElem, e3 *zpElem,
	vx *zpElem, vy *zpElem,
	v1x *zpElem, v1y *zpElem,
	qx *zpElem, qy *zpElem,
	f *qdElem, f0 *qdElem) {
	computeABCLine(e0, e1, e2, e3, vx, vy, v1x, v1y)
	millerEvalFn(f0, e1, e2, e3, qx, qy)
	f.mul(f, f0)
}

// projection operation of type A pairing
// the in1/in2 parameters belong to E(F_q), and the out belongs to F_q^2
// out hold the projection calculation result
func pairingProj(out *qdElem, in1 *ecPoint, in2 *ecPoint, pairing *Pairing) {
	// appended data handle
	data := pairing.data
	// in1 as V point, in2 as Q point
	v := in1
	qx := in2.x
	qy := in2.y
	vx := v.x
	vy := v.y
	// temporary value holder
	v1 := newEcPoint(in1.curve)
	v1x := v1.x
	v1y := v1.y
	// quadratic
	f := newQdElem(data.fq2).setIdentity()
	f0 := newQdElem(data.fq2)
	f1 := newQdElem(data.fq2)
	// Z/pZ
	e0 := newZpZero(data.fq)
	e1 := newZpZero(data.fq)
	e2 := newZpZero(data.fq)
	e3 := newZpZero(data.fq)
	z := newZpOne(data.fq)
	z2 := newZpOne(data.fq)
	// projection procedure
	var i int
	for ; i < data.exp1; i++ {
		// f = f^2 g_V, V(Q)
		// where g_V,V = tangent at V
		f.sqr(f)
		doTangent(e0, e1, e2, e3, vx, vy, qx, qy, z, z2, f, f0)
		projDouble(e0, e1, e2, e3, vx, vy, z, z2)
	}
	pointToAffine(e0, vx, vy, z, z2)
	if data.exp1 < 0 {
		v1.neg(v)
		f1.inv(f)
	} else {
		v1.set(v)
		f1.set(f)
	}
	for ; i < data.exp2; i++ {
		f.sqr(f)
		doTangent(e0, e1, e2, e3, vx, vy, qx, qy, z, z2, f, f0)
		projDouble(e0, e1, e2, e3, vx, vy, z, z2)
	}
	f.mul(f, f1)
	pointToAffine(e0, vx, vy, z, z2)
	doLine(e0, e1, e2, e3, vx, vy, v1x, v1y, qx, qy, f, f0)
	tateexp(out, f, f0, pairing.phikonr)
}
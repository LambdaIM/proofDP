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

const (
	phiValue = "12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776"

	exp2 = 159
	exp1 = 107

	errInitPairingParam = "Failed to initialize the parameter of the pairing structure"
)

// pseudo-constant
var (
	phi *big.Int
)

func initPairing() {
	var done bool
	phi, done = new(big.Int).SetString(phiValue, radix)
	if !done {
		panic(errInitPairingParam)
	}
}

// WARNING: all the routines below would change parameters' value
// --------------------------------------------------------------
// convert P from weighted projective (Jocobian) to affine
func toAffine(tmp, pX, pY, z, zSqr *galE) {
	z.inv(z)
	tmp.sqr(z)
	pX.mul(pX, tmp) // <- X / Z^2
	tmp.mul(tmp, z)
	pY.mul(pY, tmp) // <- Y / Z^3
	z.setVI(1)
	zSqr.setVI(1) // set z, z^2 to 1
}

func projDouble(t0, t1, t2, t3, pX, pY, z, zSqr *galE) {
	// 3 * x^2 + z^4
	t0.sqr(pX)
	t1.add(t0, t0)
	t0.add(t1, t0)
	t1.sqr(zSqr)
	t0.add(t0, t1)
	// z' <- 2 * yz, zSqr' <- z'^2
	z.mul(pY, z)
	z.add(z, z)
	zSqr.sqr(z)
	// 4 * x * y^2
	t2.sqr(pY)
	t1.mul(pX, t2)
	t1.mulI(t1, 4)
	// x' = t0^2 - 2 * t1
	t3.add(t1, t1)
	pX.sqr(t0)
	pX.sub(pX, t3)
	// 8 * y^4
	t2.sqr(t2)
	t2.mulI(t2, 8)
	// y' = t0 * (t1 - x) - t2
	t1.sub(t1, pX)
	t0.mul(t0, t1)
	pY.sub(t0, t2)
}

func projABCTan(t0, t1, t2, t3, pX, pY, z, zSqr *galE) {
	// t1 <- -(3 * x^2 + z^4)
	t1.sqr(zSqr)
	t2.sqr(pX)
	t0.add(t2, t2)
	t2.add(t0, t2)
	t1.add(t1, t2)
	t1.neg(t1)
	// t2 <- 2 * y * z^3
	t0.add(pY, pY)
	t2.mul(t0, zSqr)
	t2.mul(t2, z)
	// t3 <- -(2 * y^2 + t1 * x)
	t3.mul(pX, t1)
	// this is an interrupt step to handle the intermediate result's change
	t1.mul(t1, zSqr)
	t0.mul(t0, pY)
	t3.add(t3, t0)
	t3.neg(t3)
}

func calcABCLine(t0, t1, t2, t3, pX, pY, qX, qY *galE) {
	t1.sub(pY, qY)
	t2.sub(qX, pX)
	t3.mul(pX, qY)
	t0.mul(pY, qX)
	t3.sub(t3, t0)
}

func evalMiller(tq *quadE, t1, t2, t3, pX, pY *galE) {
	tq.y.mul(t1, pX)
	tq.x.sub(t3, tq.y)
	tq.y.mul(t2, pY)
}

func calcTan(t0, t1, t2, t3, pX, pY, qX, qY, z, zSqr *galE, f0, f1 *quadE) {
	projABCTan(t0, t1, t2, t3, pX, pY, z, zSqr)
	evalMiller(f1, t1, t2, t3, qX, qY)
	f0.mul(f0, f1)
}

func calcLine(t0, t1, t2, t3, aX, aY, bX, bY, cX, cY *galE, f0, f1 *quadE) {
	calcABCLine(t0, t1, t2, t3, aX, aY, bX, bY)
	evalMiller(f1, t1, t2, t3, cX, cY)
	f0.mul(f0, f1)
}

// this is a bi-linear map of the pairing from elliptic field to itself
func projPairing(out *quadE, in1, in2 *curP) {
	in1Dup := dupCurP(in1)
	// intermediate result holders
	f := newQuadE().setIdentity()
	f0 := newQuadE()
	f1 := newQuadE()
	t0 := newGalZero(gFQ)
	t1 := newGalZero(gFQ)
	t2 := newGalZero(gFQ)
	t3 := newGalZero(gFQ)
	z := newGalOne(gFQ)
	zSqr := newGalOne(gFQ)

	// projection calculation
	i := int(0)
	for ; i < exp1; i++ {
		f.sqr(f)
		calcTan(t0, t1, t2, t3, in1.x, in1.y, in2.x, in2.y, z, zSqr, f, f0)
		projDouble(t0, t1, t2, t3, in1.x, in1.y, z, zSqr)
	}

	toAffine(t0, in1.x, in1.y, z, zSqr)
	in1Dup.set(in1)
	f1.set(f)

	for ; i < exp2; i++ {
		f.sqr(f)
		calcTan(t0, t1, t2, t3, in1.x, in1.y, in2.x, in2.y, z, zSqr, f, f0)
		projDouble(t0, t1, t2, t3, in1.x, in1.y, z, zSqr)
	}

	f.mul(f, f1)
	toAffine(t0, in1.x, in1.y, z, zSqr)
	calcLine(t0, t1, t2, t3, in1.x, in1.y, in1Dup.x, in1Dup.y, in2.x, in2.y, f, f0)
	calcTateExp(out, f, f0, phi)
}

// wrapper
func biLinearMap(a, b *curP) *quadE {
	aDup := dupCurP(a)
	bDup := dupCurP(b)
	r := newQuadE().setIdentity()
	projPairing(r, aDup, bDup)
	return r
}

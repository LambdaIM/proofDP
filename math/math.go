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

import "encoding/base64"

// package level init():
// call all initializers in proper order
func init() {
	initGalois()
	initElliptic()
	initPairing()
}

// helper wrapper, for test purpose
func toBase64Str(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func fromBase64Str(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// wrapper of inner implementation

// GaloisElem presents an element in Galois field
type GaloisElem struct {
	v *galE
}

// EllipticPoint presents a point on the elliptic curve
type EllipticPoint struct {
	v *curP
}

// QuadraticElem presents an element in the quadratic
// Galois field
type QuadraticElem struct {
	v *quadE
}

// GetGenerator returns a generator of the elliptic curve
func GetGenerator() EllipticPoint {
	return EllipticPoint{
		v: dupCurP(gen),
	}
}

// EllipticPow returns the result of power calculation on
// elliptic curve
func EllipticPow(g EllipticPoint, x GaloisElem) EllipticPoint {
	return EllipticPoint{
		v: newCurP().powN(g.v, x.v.val),
	}
}

// HashToGaloisElem maps a hash value to an Galois field
// element
func HashToGaloisElem(h []byte) GaloisElem {
	return GaloisElem{
		v: newGalE(gFR).setHash(h),
	}
}

// HashToEllipticPt maps a hash value to an Elliptic curve
// point
func HashToEllipticPt(h []byte) EllipticPoint {
	return EllipticPoint{
		v: newCurP().setHash(h),
	}
}

// BiLinearMap returns the result of bi-linear map of
// 2 elements in elliptic curve field
func BiLinearMap(u, v EllipticPoint) QuadraticElem {
	return QuadraticElem{
		v: biLinearMap(u.v, v.v),
	}
}

// QuadraticEqual validate if 2 quadratic Galois field
// elements' value is equal to each other
func QuadraticEqual(a, b QuadraticElem) bool {
	return a.v.equal(b.v)
}

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
	"crypto/sha256"
	"encoding/base64"
)

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

// ---- wrapper of inner implementation ----

// GaloisElem presents an element in Galois field
type GaloisElem struct {
	v *galE
}

// Bytes converts a GaloisElem instance to a byte slice
func (e *GaloisElem) Bytes() []byte {
	return e.v.bytes()
}

// Marshal converts a GaloisElem instance to a base64 encoded string
func (e *GaloisElem) Marshal() string {
	return toBase64Str(e.Bytes())
}

// Equal validate if 2 GaloisElem instances are mathematically equal
func (e *GaloisElem) Equal(a GaloisElem) bool {
	return e.v.equal(a.v)
}

// ParseGaloisElem trys to restore a GaloisElem instance by
// parsing given Base64 encoding string
// WARNING: the result is in gFR field
func ParseGaloisElem(s string) (GaloisElem, error) {
	bytes, err := fromBase64Str(s)
	if err != nil {
		return GaloisElem{}, err
	}

	return BytesToGaloisElem(bytes), nil
}

// EllipticPoint presents a point on the elliptic curve
type EllipticPoint struct {
	v *curP
}

// Bytes converts a EllipticPoint instance to a byte slice
func (p *EllipticPoint) Bytes() []byte {
	return p.v.bytes()
}

// Marshal converts a EllipticPoint instance to a Base64 encoded string
func (p *EllipticPoint) Marshal() string {
	return toBase64Str(p.Bytes())
}

// ParseEllipticPt trys to restore an elliptic curve point from given string
func ParseEllipticPt(s string) (EllipticPoint, error) {
	bytes, err := fromBase64Str(s)
	if err != nil {
		return EllipticPoint{}, err
	}

	return EllipticPoint{
		v: newCurP().setBytes(bytes),
	}, nil
}

// QuadraticElem presents an element in the quadratic
// Galois field
type QuadraticElem struct {
	v *quadE
}

// Bytes converts a QuadraticElem instance to a byte slice
func (e *QuadraticElem) Bytes() []byte {
	return e.v.bytes()
}

// Marshal converts a QuadraticElem instance to a Base64 encoded string
func (e *QuadraticElem) Marshal() string {
	return toBase64Str(e.Bytes())
}

// ParseQuadraticElem try to restore a QuadraticElem instance by parsing
// given string
func ParseQuadraticElem(s string) (QuadraticElem, error) {
	bytes, err := fromBase64Str(s)
	if err != nil {
		return QuadraticElem{}, err
	}

	return QuadraticElem{
		v: newQuadE().setBytes(bytes),
	}, nil
}

// GetGenerator returns a generator of the elliptic curve
func GetGenerator() EllipticPoint {
	return EllipticPoint{
		v: gen,
	}
}

// HashToGaloisElem maps a hash value to an Galois field
// element. Note that the results is in gFR.
func HashToGaloisElem(h []byte) GaloisElem {
	return GaloisElem{
		v: newGalE(gFR).setHash(h),
	}
}

// BytesToGaloisElem sets a slice of bytes to the value of
// an Galois field element. Note that the result is in gFR.
func BytesToGaloisElem(b []byte) GaloisElem {
	return GaloisElem{
		v: newGalE(gFR).setBytes(b),
	}
}

// RandGaloisElem returns a random element in the Galois
// field. Note that the result is in gFR.
func RandGaloisElem() (GaloisElem, error) {
	v, err := randGalE(gFR)
	if err != nil {
		return GaloisElem{}, err
	}
	return GaloisElem{
		v: v,
	}, nil
}

// RandEllipticPt returns a random point on the elliptic
// curve in our Galois field.
func RandEllipticPt() (EllipticPoint, error) {
	v, err := randCurP()
	if err != nil {
		return EllipticPoint{}, err
	}
	return EllipticPoint{
		v: v,
	}, nil
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

// QuadraticPow returns the result of power calculation in
// a Galois-based quadratic field
func QuadraticPow(b QuadraticElem, e GaloisElem) QuadraticElem {
	return QuadraticElem{
		v: newQuadE().powN(b.v, e.v.val),
	}
}

// QuadraticMul returns the product of given Galois-based quadratic
// field elements
func QuadraticMul(lhs, rhs QuadraticElem) QuadraticElem {
	return QuadraticElem{
		v: newQuadE().mul(lhs.v, rhs.v),
	}
}

// EllipticPow returns the result of power calculation on
// elliptic curve
func EllipticPow(g EllipticPoint, x GaloisElem) EllipticPoint {
	return EllipticPoint{
		v: newCurP().powN(g.v, x.v.val),
	}
}

// EllipticMul returns the product of the given elliptic curve points
func EllipticMul(lhs, rhs EllipticPoint) EllipticPoint {
	return EllipticPoint{
		v: newCurP().mul(lhs.v, rhs.v),
	}
}

// GaloisMul returns the product of the given Galois field elements
// Note that the result is in gFR
func GaloisMul(lhs, rhs GaloisElem) GaloisElem {
	return GaloisElem{
		v: newGalE(gFR).mul(lhs.v, rhs.v),
	}
}

// HashQuadraticToGalois maps a quadratic element to Galois field
// Note that the result is in gFR
func HashQuadraticToGalois(a QuadraticElem) GaloisElem {
	h := sha256.Sum256(a.v.bytes())
	return GaloisElem{
		v: newGalE(gFR).setHash(h[:]),
	}
}

// GaloisAdd return the sum of the given Galois fields elements
// Note that this require all the given elements comes from same field
func GaloisAdd(lhs, rhs GaloisElem) GaloisElem {
	return GaloisElem{
		v: newGalE(lhs.v.fld).add(lhs.v, rhs.v),
	}
}

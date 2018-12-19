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
	"crypto/rsa"
	"math/big"
)

// the PoC implementation for the proof of data possession
type (
	PublicKey struct {
		rsaPK *rsa.PublicKey
		blsPK *BLSPubKey
		g     *ecPoint
		u     *ecPoint
		euv   *qdElem // the euv(u, v)
	}

	SecretKey struct {
		rsaSK *rsa.PrivateKey
		blsSK *BLSPriKey
	}

	KeySet struct {
		Pk *PublicKey
		Sk *SecretKey
	}

	Proof struct {
		u *zpElem
		a *ecPoint
		r *qdElem
	}
)

// create instance
func GenKeySet(rsaPK *rsa.PublicKey, rsaSK *rsa.PrivateKey, pairing *Pairing) *KeySet {
	pk := new(PublicKey)
	pk.rsaPK = rsaPK
	sk := new(SecretKey)
	sk.rsaSK = rsaSK
	// bls
	sys := genBLSSys(pairing)
	pk.blsPK, sk.blsSK = genKeys(sys)
	// fill Pk's fields
	pk.g = sys.gen
	pk.u = randomEcPoint(pairing.g1)
	pk.euv = pairing.E(pk.u, pk.blsPK.key)
	// return instance
	return &KeySet{pk, sk }
}

// -------------------- proof related routines ------------------------ //
type Tag = *ecPoint

// create tag(an ecPoint) for *SINGLE* binary data block
// tag = powN(mul(mapDataToG1(id || index), powN(u, mapDataToZr(data)), Sk.blsSK.key)
func GenTag(pairing *Pairing,  keys *KeySet, data []byte, index []byte) Tag {
	// u^Mi
	Mi := pairing.mapDataToZr(data)
	uMi := newEcPoint(pairing.g1).set(keys.Pk.u)
	uMi.powN(uMi, Mi.v)
	// H(Wi)
	HWi := pairing.mapDataToG1(index)
	// (H(Wi) * u^Mi)^x
	r := newEcPoint(pairing.g1).mul(HWi, uMi)
	return r.powN(r, keys.Sk.blsSK.key.v)
}

type Challenge = *zpElem

func GenChallenge(pairing *Pairing, index []byte) Challenge {
	return randomZpElem(pairing.zr)
}

// we separate calculateViMi for future data block processing
// Vi * Mi
func calculateViMi(accumulation *zpElem, data []byte, challenge *zpElem) *zpElem {
	// data --> Mi
	Mi := new(big.Int).SetBytes(data)
	// challenge --> Vi
	// Vi * Mi
	ViMi := newZpElem(challenge.field).mulN(challenge, Mi)
	// accumulate the newly calculation result
	return accumulation.add(accumulation, ViMi)
}

// we separate calculateAiVi for future data block processing
// Ai * Vi
func calculateAiVi(accumulation *ecPoint, challenge *zpElem, tag *ecPoint) *ecPoint {
	// Ai = tag
	AiVi := newEcPoint(tag.curve).powN(tag, challenge.v)
	// accumulate the newly calculation result
	return accumulation.mul(accumulation, AiVi)
}

type Accumulation struct {
	Zp *zpElem
	Ec *ecPoint
}

func InitAcc(pairing *Pairing) Accumulation {
	return Accumulation{ newZpZero(pairing.zr), newEcIdentity(pairing.g1) }
}

func GenProof(pairing *Pairing, key *PublicKey, data [] byte, challenge Challenge, tag Tag) *Proof {
	acc := InitAcc(pairing)
	// r = e(u, v)^n
	n := randomZpElem(pairing.zr)
	r := newQdElem(key.euv.field).set(key.euv)
	r.powN(r, n.v)
	// Vi * Mi
	ViMi := calculateViMi(acc.Zp, data, challenge)
	// y = h(R)
	y := pairing.mapGTElemToZr(r)
	// u = n + y * u
	u := n.add(n, y.mul(y, ViMi))
	// a = ai^vi
	a := calculateAiVi(acc.Ec, challenge, tag)
	// create root instance
	return &Proof{ u, a, r }
}

// WARNING: require len(data) == len(chals) == len(tags)
// FIXME: check parameter requirements
func GenProofAcc(pairing *Pairing, key *PublicKey, data [][]byte, chals []Challenge, tags []Tag) *Proof {
	// random element on Zr
	r := randomZpElem(pairing.zr)

	// R = e(u, v)^r
	R := newQdElem(key.euv.field).set(key.euv)
	R.powN(R, r.v)

	// mu' = Sum(nu_i * m_i)
	sum := newZpZero(pairing.zr)
	for i, d := range data {
		sum = calculateViMi(sum, d, chals[i])
	}

	// gamma = h(R)
	gamma := pairing.mapGTElemToZr(R)

	// mu = r + gamma * mu'
	mu := r.add(r, gamma.mul(gamma, sum))

	// sigma = Prod(sigma_i^nu_i)
	prod := newEcIdentity(pairing.g1)
	for i, t := range tags {
		prod = calculateAiVi(prod, chals[i], t)
	}

	// return the proof
	return &Proof{ mu, prod, R }
}

// Prod(H(Wi)^Vi)
func calculateHWiVi(accumulation *ecPoint, pairing *Pairing, id []byte, challenge *zpElem) *ecPoint {
	// H(Wi)^Vi, Wi = id
	HWi := pairing.mapDataToG1(id)
	HWiVi := HWi.powN(HWi, challenge.v)
	// accumulate the newly calculation result
	return accumulation.mul(accumulation, HWiVi)
}

// check R * e(a^y, g) == e((Prod(H(Wi)^Vi))^y * u^u, v)
func Verify(pairing *Pairing, key *PublicKey, id []byte, challenge Challenge, proof *Proof) bool {
	// y = h(R)
	y := pairing.mapGTElemToZr(proof.r)
	// a^y
	ay := newEcPoint(proof.a.curve).powN(proof.a, y.v)
	// e(a^y, g)
	eayg := pairing.E(ay, key.g)
	// lhs = Re(a^y, g)
	lhs := newQdElem(proof.r.field).mul(proof.r, eayg)
	// Pi(H(Wi)^Vi)
	acc := newEcIdentity(pairing.g1)
	ProdHWiVi := calculateHWiVi(acc, pairing, id, challenge)
	// Pi(H(Wi)^Vi)^y
	ProdHWiViy := newEcPoint(ProdHWiVi.curve).powN(ProdHWiVi, y.v)
	// u^u
	uu := newEcPoint(key.u.curve).powN(key.u, proof.u.v)
	// Pi(H(Wi)^Vi)^y * u^u
	ProdHWiViyuu := ProdHWiViy.mul(ProdHWiViy, uu)
	// rhs := e((II H(Wi)^Vi)^y * u^u, v)
	rhs := pairing.E(ProdHWiViyuu, key.blsPK.key)
	// compare
	return lhs.equal(rhs)
}

func VerifyAcc(pairing *Pairing, key *PublicKey, indices [][]byte, chals []Challenge, proof *Proof) bool {
	// gamma = h(R)
	gamma := pairing.mapGTElemToZr(proof.r)

	// sigma^gamma
	sigma := newEcPoint(proof.a.curve).powN(proof.a, gamma.v)

	// e(sigma^gamma, g)
	lhsE := pairing.E(sigma, key.g)

	// lhs = R * e(sigma^gamma, g)
	lhs := newQdElem(proof.r.field).mul(proof.r, lhsE)

	// Prod(H(W_i)^nu_i)
	prod := newEcIdentity(pairing.g1)
	for i, index := range indices {
		prod = calculateHWiVi(prod, pairing, index, chals[i])
	}

	// Prod^gamma
	prodExpGamma := newEcPoint(prod.curve).powN(prod, gamma.v)

	// u^mu
	uExpMu := newEcPoint(key.u.curve).powN(key.u, proof.u.v)

	// Prod^gamma * u^mu
	item := prodExpGamma.mul(prodExpGamma, uExpMu)

	// rhs = e(rhsItem, v)
	rhs := pairing.E(item, key.blsPK.key)

	// compare result
	return lhs.equal(rhs)
}
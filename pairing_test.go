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
	"os"
	"testing"
)

// test the e(u, v) implementation
func TestPairingE(t *testing.T) {
	cfgFile, e := os.Open(ParamCfgFilePath)
	if e != nil {
		t.Fatalf("configure file loading error: %s\n", e.Error())
	}
	defer cfgFile.Close()

	// A-type parameter
	aParam, e := InitAParam(cfgFile)
	if e != nil {
		t.Fatalf("A-type parameter init error: %s\n", e.Error())
	}

	// create pairing instance using given parameter
	aPairing := GenPairingWithAParam(aParam)

	// exponents
	a := big.NewInt(10086)
	b := big.NewInt(12306)

	// G1/G2 elements
	u := randomEcPoint(aPairing.g1)
	v := randomEcPoint(aPairing.g2)

	// check e(u^a, v^b) = e(u, v)^(ab)
	ua := newEcPoint(aPairing.g1).powN(u, a)
	vb := newEcPoint(aPairing.g2).powN(v, b)

	// e(u^a, v^b)
	lhs := aPairing.E(ua, vb)

	// e(u, v)^ab
	ab := new(big.Int).Mul(a, b)
	tmp := aPairing.E(u, v)
	rhs := newQdElem(tmp.field).powN(tmp, ab)

	if !lhs.equal(rhs) {
		t.Errorf("pairing E(u, v) error:\ne(u^a, v) = %v\ne(u, v)^a = %v\n",
			lhs.toBytes(), rhs.toBytes())
	}
}

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

// BLS scheme implementation
type (
	BLSSys struct {
		pairing *Pairing
		gen     *ecPoint
	}

	BLSPubKey struct {
		sys *BLSSys
		key *ecPoint
	}

	BLSPriKey struct {
		sys *BLSSys
		key *zpElem
	}
)

// generate required parameters from BLS scheme
func genBLSSys(pairing *Pairing) *BLSSys {
	return &BLSSys{ pairing, pairing.g2.newGenerator() }
}

func genKeys(sys *BLSSys) (*BLSPubKey, *BLSPriKey) {
	// Zp -> random -> x as private key
	x := randomZpElem(sys.pairing.zr)
	// G2 -> generator^x as public key
	gx := newEcPoint(sys.pairing.g2)
	gx.powN(sys.pairing.g2.gen, x.v)
	// feedback
	return &BLSPubKey{sys, gx }, &BLSPriKey{ sys, x }
}

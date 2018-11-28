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

import "math/big"

// G cross-multiply G --> GT
type GTField struct {
	order   *big.Int
	pairing *Pairing
	qd      *qdField
}

func initPairingGT(pairing *Pairing, qdf *qdField) *GTField {
	return &GTField{pairing.r, pairing, qdf }
}

// create instance
func newGTElem(f *GTField) *qdElem {
	r := newQdElem(f.qd)
	r.setIdentity()
	return r
}

// pairing operation
// WARNING: this operation will change the content of input parameters
func pairingElems(out *qdElem, in1 *ecPoint, in2 *ecPoint) {
	pairing := out.field.pairing
	pairingProj(out, in1, in2, pairing)
}
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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testRound = 1024

func TestBasicArith(t *testing.T) {
	assert.True(t, strings.Compare(gFQ.ord.String(), orderQValue) == 0)
	assert.True(t, strings.Compare(gFR.ord.String(), orderRValue) == 0)

	for i := 0; i < testRound; i++ {
		lhs, err := randGalE(gFQ)
		assert.NoError(t, err)

		rhs, err := randGalE(gFQ)
		assert.NoError(t, err)

		sum1 := newGalE(gFQ).add(lhs, rhs)
		assert.True(t, lhs.equal(newGalE(gFQ).sub(sum1, rhs)))
		assert.True(t, rhs.equal(newGalE(gFQ).sub(sum1, lhs)))

		sum2 := newGalE(gFQ).add(lhs, newGalE(gFQ).neg(lhs))
		assert.True(t, intZero.Cmp(sum2.val) == 0)

		sum3 := newGalE(gFQ).add(rhs, rhs)
		prd := newGalE(gFQ).mulI(rhs, 2)
		assert.True(t, sum3.equal(prd))

		halfLHS := newGalE(gFQ).halve(lhs)
		assert.True(t, lhs.equal(newGalE(gFQ).add(halfLHS, halfLHS)))
	}
}

func TestMulBasedCalc(t *testing.T) {
	assert.True(t, strings.Compare(gFQ.ord.String(), orderQValue) == 0)
	assert.True(t, strings.Compare(gFR.ord.String(), orderRValue) == 0)

	for i := 0; i < testRound; i++ {
		a, err := randGalE(gFR)
		assert.NoError(t, err)

		halfA := newGalE(gFR).halve(a)
		assert.True(t, a.equal(newGalE(gFR).mulI(halfA, 2)))

		invA := newGalE(gFR).inv(a)
		assert.True(t, intOne.Cmp(newGalE(gFR).mul(a, invA).val) == 0)

		// Note that in Galois field, 'sqrtSqrA' and 'a' is *NOT*
		// necessarily equal to each other, here is an example:
		// a             = 13677254656813418447919887566878490711147897715
		// sqrtSqrA      = 717073564008638202913199358004626410694828661902
		// sqr(a) | sqrA = 437594570752624551235387947750648903569997122764
		sqrA := newGalE(gFR).sqr(a)
		assert.True(t, sqrA.isSqr())
		sqrtSqrA := newGalE(gFR).sqrt(sqrA)
		assert.True(t, sqrA.equal(newGalE(gFR).sqr(sqrtSqrA)))

		x, err := randGalE(gFR)
		assert.NoError(t, err)

		aPowX := newGalE(gFR).powV(a, x.val)
		invAPowX := newGalE(gFR).powV(invA, x.val)
		assert.True(t, intOne.Cmp(newGalE(gFR).mul(aPowX, invAPowX).val) == 0)

		// Note that for Galois elements,
		// pow(a, x.neg()) != pow(a, x.val.neg())
		aPowNegX := newGalE(gFR).powV(a, new(big.Int).Neg(x.val))
		assert.True(t, invAPowX.equal(aPowNegX))
	}
}

// TODO: need valid benchmark

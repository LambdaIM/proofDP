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
	"os"
	"testing"
)

// cfg file
const ParamCfgFilePath = "cfg/a.param"

func TestInitAParam(t *testing.T) {
	f, e := os.Open(ParamCfgFilePath)
	if e != nil {
		t.Fatalf("%s\n", e.Error())
	}
	defer f.Close()
	a, e := InitAParam(f)
	if e != nil {
		t.Fatalf("%s\n", e.Error())
	}
	if len(a.q.String()) != 154 ||
		len(a.h.String()) != 107 ||
		len(a.r.String()) != 48 ||
		a.exp2 != 159 ||
		a.exp1 != 107 ||
		a.sign1 != 1 ||
		a.sign0 != 1 {
		t.Errorf("Expected: 154, 107, 48, 159, 107, 1, 1\nOut: %d, %d, %d, %d, %d, %d, %d\n",
			len(a.q.String()),
			len(a.h.String()),
			len(a.r.String()),
			a.exp2,
			a.exp1,
			a.sign1,
			a.sign0)
	}
}

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
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
)

// configuration specific format parameter
const (
	itemCountInLine = 2
)

// a-type parameter used in BLS scheme
type AParam struct {
	exp2 int
	exp1 int
	sign1 int
	sign0 int
	r *big.Int // r = 2^exp2 + sign1 * 2^exp1 + sign0 * 1
	q *big.Int
	h *big.Int // r * h = q + 1
}

// config parsing
func readInt(in string) (int, error) {
	res, e := strconv.ParseInt(in, 10, 0)
	return int(res), e
}

func readBigInt(in string) (*big.Int, error) {
	res := big.NewInt(0)
	res, ok := res.SetString(in, 10)
	if ok {
		return res, nil
	} else {
		return nil, errors.New(fmt.Sprintf("error int parse : %s", in))
	}
}

// method to create a a-type cfg from given configure source
// WARNING: we employ a fixed A-type parameter configure file for convenience
// QUESTION: do we need a full-random parameter generate routine?
func InitAParam(input io.Reader) (*AParam, error) {
	// mount reader to the input stream
	reader := bufio.NewReader(input)
	// load all data in reader
	var res AParam
	var err error
	for {
		raw, _, e := reader.ReadLine()
		if e != nil {
			err = e
			break
		}
		line := string(raw)
		items := strings.Split(line, " ")
		if len(items) != itemCountInLine {
			err = errors.New(fmt.Sprintf("invalid format line: %s", line))
		}
		switch strings.TrimSpace(items[0]) {
		case "type":
			if strings.Compare(strings.TrimSpace(items[1]), "a") != 0 {
				err = errors.New(fmt.Sprintf("mismatched paramter type: %s", items[1]))
			}
		case "exp2":
			res.exp2, err = readInt(strings.TrimSpace(items[1]))
		case "exp1":
			res.exp1, err = readInt(strings.TrimSpace(items[1]))
		case "sign1":
			res.sign1, err = readInt(strings.TrimSpace(items[1]))
		case "sign0":
			res.sign0, err = readInt(strings.TrimSpace(items[1]))
		case "r":
			res.r, err = readBigInt(strings.TrimSpace(items[1]))
		case "q":
			res.q, err = readBigInt(strings.TrimSpace(items[1]))
		case "h":
			res.h, err = readBigInt(strings.TrimSpace(items[1]))
		default:
			err = errors.New(fmt.Sprintf("unknown field: %s", items[0]))
		}
		if err != nil {
			break
		}
	}
	if err != io.EOF {
		return nil, err
	} else {
		return &res, nil
	}
}


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
}

// helper wrapper, for test purpose
func toBase64Str(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func fromBase64Str(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

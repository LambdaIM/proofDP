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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

const rsaBitsLen = 256

const pdpRandZpList = "[68 184 241 127 79 235 134 56 113 111 149 208 54 227 98 94 226 200 157 65];[13 133 19 186 168 237 208 173 187 25 181 96 155 61 146 240 108 239 68 240];[83 198 178 228 220 251 234 235 57 165 185 138 22 62 95 181 200 149 99 169];[98 241 83 177 102 217 253 141 146 100 115 158 217 220 129 108 146 234 130 206];[126 132 62 55 28 112 198 163 171 25 42 108 117 31 155 186 191 200 7 68];[118 202 97 30 84 30 252 129 63 14 247 102 82 109 9 96 216 67 240 231];[36 219 110 149 92 55 5 66 240 190 204 176 152 107 81 13 135 34 158 104];[47 231 36 226 22 252 39 156 45 222 159 223 211 88 157 22 209 182 30 95];[58 99 46 175 53 95 149 211 159 197 67 5 253 152 205 105 168 235 100 96];[14 218 247 165 38 94 179 83 49 147 81 191 84 239 166 3 162 164 232 156];[82 37 147 120 189 19 13 30 210 8 112 54 148 232 0 167 73 40 85 66]"

func readRandZpList(p *Pairing) []*zpElem {
	r := make([]*zpElem, 0)

	splitted := strings.Split(pdpRandZpList, ";")

	for _, s := range splitted {
		nums := strings.Split(strings.Trim(s, "[]"), " ")

		numBytes := make([]byte, 0)
		for _, n := range nums {
			i, e := strconv.Atoi(strings.TrimSpace(n))
			if e != nil {
				panic(e)
			}

			numBytes = append(numBytes, byte(i))
		}

		e := newZpElem(p.zr)
		e.setBytes(numBytes)
		r = append(r, e)
	}

	return r
}

func Int2bytes(number int) []byte {
	buf := make([]byte, 4)

	buf[3] = uint8(number)
	buf[2] = uint8(number >> 8)
	buf[1] = uint8(number >> 16)
	buf[0] = uint8(number >> 24)

	return buf
}

// Prod(H(Wi)^Vi)
func prodHWiVi(acc *ecPoint, pairing *Pairing, id []byte, challenge *zpElem, t *testing.T) *ecPoint {
	t.Logf("Wi = %v\n", id)
	t.Logf("Vi = %v\n", challenge.toBytes())

	// H(Wi)^Vi, Wi = id
	HWi := pairing.mapDataToG1(id)
	t.Logf("HWi = %v\n", HWi.toBytes())

	HWiVi := HWi.powN(HWi, challenge.v)
	t.Logf("HWiVi = %v\n", HWiVi.toBytes())

	// accumulate the newly calculation result
	acc.mul(acc, HWiVi)
	t.Logf("acc = %v\n", acc.toBytes())

	return acc
}

func TestCalculateProdHWiVi(t *testing.T) {
	// load configure file
	cfgFile, e := os.Open(ParamCfgFilePath)
	if e != nil {
		t.Fatalf("proof positive sample error : %s\n", e.Error())
	}
	defer cfgFile.Close()

	// load the parameter from configure file
	aParam, e := InitAParam(cfgFile)
	if e != nil {
		t.Fatalf("proof positive sample error : %s\n", e.Error())
	}

	// create a pairing structure from the parameter
	pairing := GenPairingWithAParam(aParam)

	randZpList := readRandZpList(pairing)
	listIdx := 0

	Ns := []int{ 1, 2 } //, 3, 5 }

	for r, n := range Ns {
		t.Logf("----------------------- Round %d -----------------------\n", r)

		acc := newEcIdentity(pairing.g1)
		name := []byte("name")

		for i := 0; i < n; i++ {
			t.Logf("------------\n")
			t.Logf("index = %d\n", i)
			id := append(name, Int2bytes(i)...)
			//id := []byte(fmt.Sprintf("%s%d", name, i))
			acc = prodHWiVi(acc, pairing, id, randZpList[listIdx], t)
			listIdx = (listIdx + 1) % len(randZpList)
			t.Logf("------------\n")
		}

		t.Logf("--------------------------------------------------------\n")
	}
}

func TestProofDPPositive(t *testing.T) {
	// load configure file
	cfgFile, e := os.Open(ParamCfgFilePath)
	if e != nil {
		t.Fatalf("proof positive sample error : %s\n", e.Error())
	}
	defer cfgFile.Close()

	// load the parameter from configure file
	aParam, e := InitAParam(cfgFile)
	if e != nil {
		t.Fatalf("proof positive sample error : %s\n", e.Error())
	}

	// create a pairing structure from the parameter
	pairing := GenPairingWithAParam(aParam)

	// ----------------------------------------
	// the math infrastructure preparation done
	// these procedure required by all roles
	// ----------------------------------------

	// generate rsa keys
	rsaPriKey, e := rsa.GenerateKey(rand.Reader, rsaBitsLen)
	if e != nil {
		t.Fatalf("proof positive sample error : %s\n", e.Error())
	}
	rsaPubKey := &rsaPriKey.PublicKey

	// generate the key set for proof of data possession
	keySet := GenKeySet(rsaPubKey, rsaPriKey, pairing)

	// sample data for the proof PoC
	sampleData := []byte("Demo data for the ProofDP PoC")
	// sample index for data location
	sampleIndex := []byte("Demo-ID")

	// ------------- the data owner --------------- //
	// generate the data tag
	tag := GenTag(pairing, keySet, sampleData, sampleIndex)

	// ------------- the third party audit ---------------- //
	// generate the challenge for data possession validation
	challenge := GenChallenge(pairing, sampleIndex)

	// ------------- the storage provider ---------------- //
	// response to the challenge
	// Note : the sampleData could be found using sampleIndex
	proof := GenProof(pairing, keySet.Pk, sampleData, challenge, tag)

	// ------------- the third party audit ---------------- //
	if !Verify(pairing, keySet.Pk, sampleIndex, challenge, proof) {
		t.Errorf("proof positive sample error : positive sample failed\n")
	}
}

func TestProofDPNegative(t *testing.T) {
	// load configure file
	cfgFile, e := os.Open(ParamCfgFilePath)
	if e != nil {
		t.Fatalf("proof negative sample error : %s\n", e.Error())
	}
	defer cfgFile.Close()

	// load the parameter from configure file
	aParam, e := InitAParam(cfgFile)
	if e != nil {
		t.Fatalf("proof negative sample error : %s\n", e.Error())
	}

	// create a pairing structure from the parameter
	pairing := GenPairingWithAParam(aParam)

	// ----------------------------------------
	// the math infrastructure preparation done
	// these procedure required by all roles
	// ----------------------------------------

	// generate rsa keys
	rsaPriKey, e := rsa.GenerateKey(rand.Reader, rsaBitsLen)
	if e != nil {
		t.Fatalf("proof negative sample error : %s\n", e.Error())
	}
	rsaPubKey := &rsaPriKey.PublicKey

	// generate the key set for proof of data possession
	keySet := GenKeySet(rsaPubKey, rsaPriKey, pairing)

	// sample data for the proof PoC
	sampleData := []byte("Demo data for the ProofDP PoC")
	// sample index for data location
	sampleIndex := []byte("Demo-ID")

	// ------------- the data owner --------------- //
	// generate the data tag
	tag := GenTag(pairing, keySet, sampleData, sampleIndex)

	// ------------- the third party audit ---------------- //
	// generate the challenge for data possession validation
	challenge := GenChallenge(pairing, sampleIndex)

	// ------------- the storage provider ---------------- //
	// a storage change simulation
	alteredData := []byte("Demo data for the ProofDP PoD")
	// response to the given challenge
	proof := GenProof(pairing, keySet.Pk, alteredData, challenge, tag)

	// ------------- the third party audit ---------------- //
	if Verify(pairing, keySet.Pk, sampleIndex, challenge, proof) {
		t.Errorf("proof negative sample error : negative sample failed\n")
	}
}

// a demo file content slicing implementation
// slice file content into sliceCount-numbered data chunks
func DemoFileSlice(path string, sliceCount int) ([][]byte, error) {
	// load file info
	file, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer file.Close()

	info, e := file.Stat()
	if e != nil {
		return nil, e
	}

	chunkSize := (info.Size() + int64(sliceCount) - 1) / int64(sliceCount)
	r := make([][]byte, sliceCount)

	for i := 0; i < sliceCount; i++ {
		tmp := make([]byte, chunkSize)
		_, e := file.Read(tmp)
		if e != nil && e != io.EOF {
			return nil, e
		}
		r[i] = tmp
	}

	return r, nil
}

func TestProofDPFile(t *testing.T) {
	// load configure file
	cfgFile, e := os.Open(ParamCfgFilePath)
	if e != nil {
		t.Fatalf("file sample error : %s\n", e.Error())
	}
	defer cfgFile.Close()

	// load the parameter from configure file
	aParam, e := InitAParam(cfgFile)
	if e != nil {
		t.Fatalf("file sample error : %s\n", e.Error())
	}

	// create a pairing structure from the parameter
	pairing := GenPairingWithAParam(aParam)

	// ----------------------------------------
	// the math infrastructure preparation done
	// these procedure required by all roles
	// ----------------------------------------

	// generate rsa keys
	rsaPriKey, e := rsa.GenerateKey(rand.Reader, rsaBitsLen)
	if e != nil {
		t.Fatalf("file sample error : %s\n", e.Error())
	}
	rsaPubKey := &rsaPriKey.PublicKey

	// generate the key set for proof of data possession
	keySet := GenKeySet(rsaPubKey, rsaPriKey, pairing)

	// sample data
	sampleFile := "proof_test.go"
	// sample slicing param
	sampleSliceCount := 3
	// sample index param
	sampleIdPrefix := "sample_"

	sampleData, e := DemoFileSlice(sampleFile, sampleSliceCount)
	if e != nil {
		t.Fatalf("file sample error : %s\n", e.Error())
	}

	// ------------- the data owner --------------- //
	tagTable := make(map[string]Tag)
	for i, data := range sampleData {
		// add index/data pair
		index := fmt.Sprintf("%s%d", sampleIdPrefix, i)
		// generate the data tag
		tagTable[string(index)] = GenTag(pairing, keySet, data, []byte(index))
	}

	// -------------- TPA --------------- //
	chalTable := make(map[string]Challenge)
	for i := 0; i < sampleSliceCount; i++ {
		// generate the challenge for data possession validation
		index := fmt.Sprintf("%s%d", sampleIdPrefix, i)
		chalTable[index] = GenChallenge(pairing, []byte(index))
	}

	// ------------- the storage provider ---------------- //
	proofTable := make(map[string]*Proof)
	for i, data := range sampleData {
		// fetch the tag & challenge
		index := fmt.Sprintf("%s%d", sampleIdPrefix, i)
		tag := tagTable[index]
		chal := chalTable[index]
		// generate the proof
		proofTable[index] = GenProof(pairing, keySet.Pk, data, chal, tag)
	}

	// -------------- TPA --------------- //
	for i := 0; i < sampleSliceCount; i++ {
		// fetch the tag/challenge & the proof
		index := fmt.Sprintf("%s%d", sampleIdPrefix, i)
		chal := chalTable[index]
		proof := proofTable[index]
		if !Verify(pairing, keySet.Pk, []byte(index), chal, proof) {
			t.Errorf("file sample error : verify failed for #%d(indexed as %s) data chunk\n",
				i, index)
		}
	}
}

func TestProofDPAcc(t *testing.T) {
	// load configure file
	cfgFile, e := os.Open(ParamCfgFilePath)
	if e != nil {
		t.Fatalf("acc sample error : %s\n", e.Error())
	}
	defer cfgFile.Close()

	// load the parameter from configure file
	aParam, e := InitAParam(cfgFile)
	if e != nil {
		t.Fatalf("acc sample error : %s\n", e.Error())
	}

	// create a pairing structure from the parameter
	pairing := GenPairingWithAParam(aParam)

	// ----------------------------------------
	// the math infrastructure preparation done
	// these procedure required by all roles
	// ----------------------------------------

	// generate rsa keys
	rsaPriKey, e := rsa.GenerateKey(rand.Reader, rsaBitsLen)
	if e != nil {
		t.Fatalf("acc sample error : %s\n", e.Error())
	}
	rsaPubKey := &rsaPriKey.PublicKey

	// generate the key set for proof of data possession
	keySet := GenKeySet(rsaPubKey, rsaPriKey, pairing)

	// sample data
	sampleFile := "proof_test.go"
	// sample slicing param
	sampleSliceCount := 3
	// sample index param
	sampleIdPrefix := "sample_"

	sampleData, e := DemoFileSlice(sampleFile, sampleSliceCount)
	if e != nil {
		t.Fatalf("acc sample error : %s\n", e.Error())
	}

	// ------------- the data owner --------------- //
	indices := make([][]byte, 0)
	tags := make([]Tag, 0)
	for i, data := range sampleData {
		// add index/data pair
		index := fmt.Sprintf("%s%d", sampleIdPrefix, i)
		indices = append(indices, []byte(index))
		// generate the data tag
		tags = append(tags, GenTag(pairing, keySet, data, []byte(index)))
	}

	// -------------- TPA --------------- //
	chals := make([]Challenge, 0)
	for i := 0; i < sampleSliceCount; i++ {
		// generate the challenge for data possession validation
		index := fmt.Sprintf("%s%d", sampleIdPrefix, i)
		chals = append(chals, GenChallenge(pairing, []byte(index)))
	}

	// ------------- the storage provider ---------------- //
	proof := GenProofAcc(pairing, keySet.Pk, sampleData, chals, tags)

	// -------------- TPA --------------- //
	if !VerifyAcc(pairing, keySet.Pk, indices, chals, proof) {
		t.Errorf("acc sample error : verify failed\n")
	}
}
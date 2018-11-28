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
	"testing"
)

const rsaBitsLen = 256

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
	proof := GenProof(pairing, keySet.Pk, sampleData, challenge, tag, InitAccumulation(pairing))

	// ------------- the third party audit ---------------- //
	if !Verify(pairing, keySet.Pk, sampleIndex, challenge, proof, InitAccumulation(pairing)) {
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
	proof := GenProof(pairing, keySet.Pk, alteredData, challenge, tag, InitAccumulation(pairing))

	// ------------- the third party audit ---------------- //
	if Verify(pairing, keySet.Pk, sampleIndex, challenge, proof, InitAccumulation(pairing)) {
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
		proofTable[index] = GenProof(pairing, keySet.Pk, data, chal, tag, InitAccumulation(pairing))
	}

	// -------------- TPA --------------- //
	for i := 0; i < sampleSliceCount; i++ {
		// fetch the tag/challenge & the proof
		index := fmt.Sprintf("%s%d", sampleIdPrefix, i)
		chal := chalTable[index]
		proof := proofTable[index]
		if !Verify(pairing, keySet.Pk, []byte(index), chal, proof, InitAccumulation(pairing)) {
			t.Errorf("file sample error : verify failed for #%d(indexed as %s) data chunk\n",
				i, index)
		}
	}
}
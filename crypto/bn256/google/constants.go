// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bn256

import (
	"math/big"
)

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

// u is the BN parameter that determines the prime: 1868033³.
var u = bigFromBase10("4965661367192848881")

// p is a prime over which we form a basic field: 36u⁴+36u³+24u²+6u+1.
var P = bigFromBase10("21888242871839275222246405745257275088696311157297823662689037894645226208583")

// Order is the number of elements in both G₁ and G₂: 36u⁴+36u³+18u²+6u+1.
var Order = bigFromBase10("21888242871839275222246405745257275088548364400416034343698204186575808495617")

// XiTo2PMinusTnum1 is a prime over which we form a basic field.
var XiToPMinusTnum1 = new(big.Int).Mul(big.NewInt(5e+5), big.NewInt(1e+5))

// XiTo2PMinusTnum2 is a prime over which we form a basic field.
var XiToPMinusTnum2 = new(big.Int).Mul(big.NewInt(1e+8), big.NewInt(1e+5))

//XiTo2PMinusTacc1 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc1 = []byte{149, 92, 223, 37, 106, 209, 25, 37, 169, 212, 97, 197, 189, 54, 202, 105, 249, 127, 65, 162, 122}

//XiTo2PMinusTacc2 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc2 = []byte{149, 144, 88, 186, 194, 232, 41, 180, 130, 190, 165, 226, 42, 228, 46, 164, 57, 4, 200, 154, 190}

//XiTo2PMinusTacc3 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc3 = []byte{149, 160, 77, 94, 169, 247, 17, 7, 113, 34, 96, 185, 74, 20, 125, 73, 127, 131, 35, 234, 173}

//XiTo2PMinusTacc4 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc4 = []byte{149, 33, 47, 200, 108, 35, 92, 118, 98, 191, 80, 189, 13, 220, 140, 164, 191, 60, 112, 76, 117}

//XiTo2PMinusTacc5 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc5 = []byte{149, 140, 160, 246, 159, 215, 51, 141, 160, 104, 95, 243, 55, 36, 176, 62, 156, 125, 46, 96, 193}

//XiTo2PMinusTacc6 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc6 = []byte{149, 87, 198, 212, 197, 22, 193, 93, 231, 10, 252, 121, 98, 84, 250, 101, 194, 175, 109, 246, 162}

// xiToPMinus1Over6 is ξ^((p-1)/6) where ξ = i+9.
var xiToPMinus1Over6 = &gfP2{bigFromBase10("16469823323077808223889137241176536799009286646108169935659301613961712198316"), bigFromBase10("8376118865763821496583973867626364092589906065868298776909617916018768340080")}

// xiToPMinus1Over3 is ξ^((p-1)/3) where ξ = i+9.
var xiToPMinus1Over3 = &gfP2{bigFromBase10("10307601595873709700152284273816112264069230130616436755625194854815875713954"), bigFromBase10("21575463638280843010398324269430826099269044274347216827212613867836435027261")}

// xiToPMinus1Over2 is ξ^((p-1)/2) where ξ = i+9.
var xiToPMinus1Over2 = &gfP2{bigFromBase10("3505843767911556378687030309984248845540243509899259641013678093033130930403"), bigFromBase10("2821565182194536844548159561693502659359617185244120367078079554186484126554")}

// xiToPSquaredMinus1Over3 is ξ^((p²-1)/3) where ξ = i+9.
var xiToPSquaredMinus1Over3 = bigFromBase10("21888242871839275220042445260109153167277707414472061641714758635765020556616")

// xiTo2PSquaredMinus2Over3 is ξ^((2p²-2)/3) where ξ = i+9 (a cubic root of unity, mod p).
var xiTo2PSquaredMinus2Over3 = bigFromBase10("2203960485148121921418603742825762020974279258880205651966")

// xiToPSquaredMinus1Over6 is ξ^((1p²-1)/6) where ξ = i+9 (a cubic root of -1, mod p).
var xiToPSquaredMinus1Over6 = bigFromBase10("21888242871839275220042445260109153167277707414472061641714758635765020556617")

// xiTo2PMinus2Over3 is ξ^((2p-2)/3) where ξ = i+9.
var xiTo2PMinus2Over3 = &gfP2{bigFromBase10("19937756971775647987995932169929341994314640652964949448313374472400716661030"), bigFromBase10("2581911344467009335267311115468803099551665605076196740867805258568234346338")}

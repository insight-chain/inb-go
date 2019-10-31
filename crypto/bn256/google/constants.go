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
var XiTo2PMinusTacc1 = []byte{149, 80, 137, 227, 60, 253, 240, 174, 42, 61, 22, 248, 133, 77, 35, 131, 164, 53, 138, 150}

//XiTo2PMinusTacc2 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc2 = []byte{149, 191, 36, 82, 139, 52, 12, 242, 186, 147, 195, 5, 209, 47, 82, 245, 248, 79, 113, 19}

//XiTo2PMinusTacc3 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc3 = []byte{149, 169, 227, 120, 40, 18, 229, 152, 55, 22, 154, 210, 219, 186, 142, 89, 63, 241, 121, 134}

//XiTo2PMinusTacc4 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc4 = []byte{149, 120, 51, 108, 108, 194, 170, 186, 94, 154, 14, 134, 212, 83, 89, 31, 128, 207, 31, 190}

//XiTo2PMinusTacc5 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc5 = []byte{149, 148, 86, 132, 241, 47, 108, 243, 16, 119, 156, 199, 14, 27, 20, 24, 245, 142, 17, 61}

//XiTo2PMinusTacc6 is Tacc, represented as little-endian 64-bit words.
var XiTo2PMinusTacc6 = []byte{149, 128, 30, 204, 127, 145, 176, 159, 42, 116, 217, 155, 15, 153, 114, 165, 198, 179, 153, 87}

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

package schnorr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)
// 19.09.05 by spl begin
var (
	// Curve is a KoblitzCurve which implements secp256k1.
	Curve = btcec.S256()
	// One holds a big integer of 1
	One = new(big.Int).SetInt64(1)
	// Two holds a big integer of 2
	Two = new(big.Int).SetInt64(2)
	// Three holds a big integer of 3
	Three = new(big.Int).SetInt64(3)
	// Four holds a big integer of 4
	Four = new(big.Int).SetInt64(4)
	// Seven holds a big integer of 7
	Seven = new(big.Int).SetInt64(7)
	// N2 holds a big integer of N-2
	N2 = new(big.Int).Sub(Curve.N, Two)
)
// 19.09.05 by spl begin
// Sign a 32 byte message with the private key, returning a 64 byte signature.
func Sign(privateKeyStr []byte, message []byte) ([]byte, error) {
	privateKey := byteToInt(privateKeyStr)
	sig := [64]byte{}
	if privateKey.Cmp(One) < 0 || privateKey.Cmp(new(big.Int).Sub(Curve.N, One)) > 0 {
		return sig[:], errors.New("the private key must be an integer in the range 1..n-1")
	}

	d := intToByte(privateKey)
	k0, err := deterministicGetK0(d, message)
	if err != nil {
		return sig[:], err
	}

	Rx, Ry := Curve.ScalarBaseMult(intToByte(k0))
	k := getK(Ry, k0)

	Px, Py := Curve.ScalarBaseMult(d)
	rX := intToByte(Rx)
	e := getE(Px, Py, rX, message)
	e.Mul(e, privateKey)
	k.Add(k, e)
	k.Mod(k, Curve.N)

	copy(sig[:32], rX)
	copy(sig[32:], intToByte(k))
	return sig[:], nil
}

// 19.09.05 by spl begin
// Verify a 64 byte signature of a 32 byte message against the public key.
// Returns an error if verification fails.
func Verify(publicKey []byte, message []byte, signature [64]byte) (bool, error) {
	Px, Py := Unmarshal(Curve, publicKey[:])

	if Px == nil || Py == nil || !Curve.IsOnCurve(Px, Py) {
		return false, errors.New("signature verification failed")
	}
	r := new(big.Int).SetBytes(signature[:32])
	if r.Cmp(Curve.P) >= 0 {
		return false, errors.New("r is larger than or equal to field size")
	}
	s := new(big.Int).SetBytes(signature[32:])
	if s.Cmp(Curve.N) >= 0 {
		return false, errors.New("s is larger than or equal to curve order")
	}

	e := getE(Px, Py, intToByte(r), message)
	sGx, sGy := Curve.ScalarBaseMult(intToByte(s))
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(Px, Py, intToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx, Ry := Curve.Add(sGx, sGy, ePx, ePy)

	if (Rx.Sign() == 0 && Ry.Sign() == 0) || big.Jacobi(Ry, Curve.P) != 1 || Rx.Cmp(r) != 0 {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}

// 19.09.05 by spl begin
// BatchVerify verifies a list of 64 byte signatures of 32 byte messages against the public keys.
// Returns an error if verification fails.
func BatchVerify(publicKeys [][]byte, messages [][]byte, signatures [][]byte) (bool, error) {
	if publicKeys == nil || len(publicKeys) == 0 {
		return false, errors.New("publicKeys must be an array with one or more elements")
	}
	if messages == nil || len(messages) == 0 {
		return false, errors.New("messages must be an array with one or more elements")
	}
	if signatures == nil || len(signatures) == 0 {
		return false, errors.New("signatures must be an array with one or more elements")
	}
	if len(publicKeys) != len(messages) || len(messages) != len(signatures) {
		return false, errors.New("all parameters must be an array with the same length")
	}

	ls := new(big.Int).SetInt64(0)
	a := new(big.Int).SetInt64(1)
	rsx, rsy := new(big.Int), new(big.Int)

	for i, signature := range signatures {
		publicKey := publicKeys[i]
		message := messages[i]
		Px, Py := Unmarshal(Curve, publicKey[:])

		if Px == nil || Py == nil || !Curve.IsOnCurve(Px, Py) {
			return false, errors.New("signature verification failed")
		}
		r := new(big.Int).SetBytes(signature[:32])
		if r.Cmp(Curve.P) >= 0 {
			return false, errors.New("r is larger than or equal to field size")
		}
		s := new(big.Int).SetBytes(signature[32:])
		if s.Cmp(Curve.N) >= 0 {
			return false, errors.New("s is larger than or equal to curve order")
		}

		e := getE(Px, Py, intToByte(r), message)

		r2 := new(big.Int).Exp(r, Three, nil)
		r2.Add(r2, Seven)
		c := r2.Mod(r2, Curve.P)
		exp := new(big.Int).Add(Curve.P, One)
		exp.Div(exp, Four)

		y := new(big.Int).Exp(c, exp, Curve.P)

		if new(big.Int).Exp(y, Two, Curve.P).Cmp(c) != 0 {
			return false, errors.New("signature verification failed")
		}

		Rx, Ry := r, y

		if i != 0 {
			var err error
			a, err = deterministicGetRandA()
			if err != nil {
				return false, err
			}
		}

		aRx, aRy := Curve.ScalarMult(Rx, Ry, intToByte(a))
		aePx, aePy := Curve.ScalarMult(Px, Py, e.Mul(e, a).Bytes())
		rsx, rsy = Curve.Add(rsx, rsy, aRx, aRy)
		rsx, rsy = Curve.Add(rsx, rsy, aePx, aePy)
		s.Mul(s, a)
		ls.Add(ls, s)
	}

	Gx, Gy := Curve.ScalarBaseMult(intToByte(ls.Mod(ls, Curve.N)))
	if Gx.Cmp(rsx) != 0 || Gy.Cmp(rsy) != 0 {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}

// 19.09.05 by spl begin
// AggregateSignatures aggregates multiple signatures of different private keys over
// the same message into a single 64 byte signature.
func AggregateSignatures(privateKeys []*big.Int, message []byte) ([]byte, error) {
	sig := []byte{}
	if privateKeys == nil || len(privateKeys) == 0 {
		return sig, errors.New("privateKeys must be an array with one or more elements")
	}

	k0s := []*big.Int{}
	Px, Py := new(big.Int), new(big.Int)
	Rx, Ry := new(big.Int), new(big.Int)
	for _, privateKey := range privateKeys {
		if privateKey.Cmp(One) < 0 || privateKey.Cmp(new(big.Int).Sub(Curve.N, One)) > 0 {
			return sig, errors.New("the private key must be an integer in the range 1..n-1")
		}

		d := intToByte(privateKey)
		k0i, err := deterministicGetK0(d, message)
		if err != nil {
			return sig, err
		}

		RiX, RiY := Curve.ScalarBaseMult(intToByte(k0i))
		PiX, PiY := Curve.ScalarBaseMult(d)

		k0s = append(k0s, k0i)

		Rx, Ry = Curve.Add(Rx, Ry, RiX, RiY)
		Px, Py = Curve.Add(Px, Py, PiX, PiY)
	}

	rX := intToByte(Rx)
	e := getE(Px, Py, rX, message)
	s := new(big.Int).SetInt64(0)

	for i, k0 := range k0s {
		k := getK(Ry, k0)
		k.Add(k, new(big.Int).Mul(e, privateKeys[i]))
		s.Add(s, k)
	}

	copy(sig[:32], rX)
	copy(sig[32:], intToByte(s.Mod(s, Curve.N)))
	return sig, nil
}

// 19.09.05 by spl begin
func getE(Px, Py *big.Int, rX []byte, m []byte) *big.Int {
	r := append(rX, Marshal(Curve, Px, Py)...)
	r = append(r, m[:]...)
	h := sha256.Sum256(r)
	i := new(big.Int).SetBytes(h[:])
	return i.Mod(i, Curve.N)
}

// 19.09.05 by spl begin
func getK(Ry, k0 *big.Int) *big.Int {
	if big.Jacobi(Ry, Curve.P) == 1 {
		return k0
	}
	return k0.Sub(Curve.N, k0)
}

// 19.09.05 by spl begin
func deterministicGetK0(d []byte, message []byte) (*big.Int, error) {
	h := sha256.Sum256(append(d, message[:]...))
	i := new(big.Int).SetBytes(h[:])
	k0 := i.Mod(i, Curve.N)
	if k0.Sign() == 0 {
		return nil, errors.New("k0 is zero")
	}

	return k0, nil
}

// 19.09.05 by spl begin
func deterministicGetRandA() (*big.Int, error) {
	a, err := rand.Int(rand.Reader, N2)
	if err != nil {
		return nil, err
	}

	return a.Add(a, One), nil
}

// 19.09.05 by spl begin
func intToByte(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}

// 19.09.05 by spl begin
func byteToInt(str []byte ) *big.Int{
	return new(big.Int).SetBytes(str)
}

// 19.09.05 by spl begin
// Marshal converts a point into the form specified in section 2.3.3 of the
// SEC 1 standard.
func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 1+byteLen)
	ret[0] = 2 // compressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	ret[0] += byte(y.Bit(0))
	return ret
}

// 19.09.05 by spl begin
// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On
// error, x = nil.
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 {
		return
	}
	if len(data) != 1+byteLen {
		return
	}

	x0 := new(big.Int).SetBytes(data[1 : 1+byteLen])
	P := curve.Params().P
	ySq := new(big.Int)
	ySq.Exp(x0, Three, P)
	ySq.Add(ySq, Seven)
	ySq.Mod(ySq, P)
	y0 := new(big.Int)
	P1 := new(big.Int).Add(P, One)
	d := new(big.Int).Mod(P1, Four)
	P1.Sub(P1, d)
	P1.Div(P1, Four)
	y0.Exp(ySq, P1, P)

	if new(big.Int).Exp(y0, Two, P).Cmp(ySq) != 0 {
		return
	}
	if y0.Bit(0) != uint(data[0]&1) {
		y0.Sub(P, y0)
	}
	x, y = x0, y0
	return
}
func RecoverCompact(curve *btcec.KoblitzCurve, signature,
	hash []byte) (*ecdsa.PublicKey, bool, error) {
	bitlen := (curve.BitSize + 7) / 8
	if len(signature) != 1+bitlen*2 {
		return nil, false, errors.New("invalid compact signature size")
	}

	iteration := int((signature[0] - 27) & ^byte(4))

	// format is <header byte><bitlen R><bitlen S>
	sig := &Signature{
		R: new(big.Int).SetBytes(signature[1 : bitlen+1]),
		S: new(big.Int).SetBytes(signature[bitlen+1:]),
	}
	// The iteration used here was encoded
	key, err := recoverKeyFromSignature(curve, sig, hash, iteration, false)
	if err != nil {
		return nil, false, err
	}

	return key, ((signature[0] - 27) & 4) == 4, nil
}

func recoverKeyFromSignature(curve *btcec.KoblitzCurve, sig *Signature, msg []byte,
	iter int, doChecks bool) (*ecdsa.PublicKey, error) {
	// 1.1 x = (n * i) + r
	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, sig.R)
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	// convert 02<Rx> to point R. (step 1.2 and 1.3). If we are on an odd
	// iteration then 1.6 will be done with -R, so we calculate the other
	// term when uncompressing the point.
	Ry, err := decompressPoint(curve, Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}

	// 1.4 Check n*R is point at infinity
	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	// 1.5 calculate e from message using the same algorithm as ecdsa
	// signature calculation.
	e := hashToInt(msg, curve)

	// Step 1.6.1:
	// We calculate the two terms sR and eG separately multiplied by the
	// inverse of r (from the signature). We then add them to calculate
	// Q = r^-1(sR-eG)
	invr := new(big.Int).ModInverse(sig.R, curve.Params().N)

	// first term.
	invrS := new(big.Int).Mul(invr, sig.S)
	invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invrS.Bytes())

	// second term.
	e.Neg(e)
	e.Mod(e, curve.Params().N)
	e.Mul(e, invr)
	e.Mod(e, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(e.Bytes())

	// TODO: this would be faster if we did a mult and add in one
	// step to prevent the jacobian conversion back and forth.
	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}

type Signature struct {
	R       *big.Int
	S       *big.Int
	sigType SignatureType
}

type SignatureType uint8

const (
	// SignatureTypeECDSA defines an ecdsa signature
	SignatureTypeECDSA SignatureType = iota

	// SignatureTypeSchnorr defines a schnorr signature
	SignatureTypeSchnorr
)

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func decompressPoint(curve *btcec.KoblitzCurve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)
	x3.Mod(x3, curve.Params().P)

	// Now calculate sqrt mod p of x^3 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	y := new(big.Int).Exp(x3, curve.QPlus1Div4(), curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}

	// Check that y is a square root of x^3 + B.
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.Params().P)
	if y2.Cmp(x3) != 0 {
		return nil, fmt.Errorf("invalid square root")
	}

	// Verify that y-coord has expected parity.
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}

	return y, nil
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}
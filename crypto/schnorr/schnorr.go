package schnorr
/*
#cgo CFLAGS: -I./libsecp256k1
#cgo CFLAGS: -I./libsecp256k1/src/
#define USE_NUM_NONE
#define USE_FIELD_10X26
#define USE_FIELD_INV_BUILTIN
#define USE_SCALAR_8X32
#define USE_SCALAR_INV_BUILTIN
#define NDEBUG
#include "secp256k1/libsecp256k1/src/secp256k1.c"
#include "secp256k1/libsecp256k1/src/modules/schnorr/main_impl.h"
#include "ext.h"

typedef void (*callbackFunc) (const char* msg, void* data);
extern void secp256k1GoPanicIllegal(const char* msg, void* data);
extern void secp256k1GoPanicError(const char* msg, void* data);
*/
import "C"

import (
	"errors"
	"unsafe"
)
var context *C.secp256k1_context

var (
	ErrInvalidMsgLen       = errors.New("invalid message length, need 32 bytes")
	ErrInvalidSignatureLen = errors.New("invalid signature length")
	ErrInvalidRecoveryID   = errors.New("invalid signature recovery id")
	ErrInvalidKey          = errors.New("invalid private key")
	ErrInvalidPubkey       = errors.New("invalid public key")
	ErrSignFailed          = errors.New("signing failed")
	ErrRecoverFailed       = errors.New("recovery failed")
)

// 19.09.05 by spl begin
// Sign a 32 byte message with the private key, returning a 64 byte signature.
func Sign(privateKey []byte, message []byte) ([]byte, error) {
	if len(message) != 32 {
		return nil, ErrInvalidMsgLen
	}
	if len(privateKey) != 32 {
		return nil, ErrInvalidKey
	}
	privateKeyData := (*C.uchar)(unsafe.Pointer(&privateKey[0]))
	var (
		msgdata   = (*C.uchar)(unsafe.Pointer(&message[0]))
		sig     = make([]byte, 64)
	)

	C.secp256k1_schnorr_sign(context, sig, msgdata, privateKeyData, nil, nil)
	return sig, nil
}

//// 19.09.05 by spl begin
//// Verify a 64 byte signature of a 32 byte message against the public key.
//// Returns an error if verification fails.
//func Verify(publicKey []byte, message []byte, signature [64]byte) (bool, error) {
//
//}


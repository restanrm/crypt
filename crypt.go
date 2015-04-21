package crypt

import (
	"crypto/rand"
	"encoding/base64"
	"unsafe"
)

/*
#cgo LDFLAGS: -lcrypt
#define _GNU_SOURCE
#include <crypt.h>
#include <stdlib.h>
*/
import "C"

func encodeString(src []byte) string {
	encoding := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./")
	return encoding.EncodeToString(src)
}

func generate_salt() []byte {
	out := make([]byte, 32)
	rand.Read(out)
	return out
}

func Crypt(password, salt string) string {
	cpass := C.CString(password)
	csalt := C.CString(salt)
	hash := C.GoString(C.crypt(cpass, csalt))
	C.free(unsafe.Pointer(cpass))
	C.free(unsafe.Pointer(csalt))
	return hash
}

func GenerateFromPassword(password string) string {
	salt := "$6$" + encodeString(generate_salt())[:16] + "$"
	return Crypt(password, salt)
}

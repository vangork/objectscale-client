//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

package pkg

/*
#cgo CFLAGS: -I${SRCDIR}/../../c/
#cgo LDFLAGS: -L${SRCDIR}/../../target/release/ -lobjectscale_client -Wl,-rpath,${SRCDIR}/../../target/release/ -Wl,-rpath,$ORIGIN
#include "objectscale_client.h"
*/
import "C"
import (
	"fmt"
	"reflect"
	"unsafe"
)

type (
	cu8ptr = *C.uint8_t
	usize  = C.uintptr_t
	cusize = C.size_t
	cint   = C.int
	ci32   = C.int32_t
	cu32   = C.uint32_t
	ci64   = C.int64_t
	cu64   = C.uint64_t
	cbool  = C.bool
)

func copyAndDestroyRCString(b C.RCString) []byte {
	if isRCStringEmpty(b) {
		return nil
	}
	res := C.GoBytes(unsafe.Pointer(b.ptr), cint(b.len))
	C.free_rcstring(b)
	return res
}

func isRCStringEmpty(b C.RCString) bool {
	return b.ptr == cu8ptr(nil) || b.len == usize(0) || b.cap == usize(0)
}

func fromRCString(b C.RCString) string {
	if isRCStringEmpty(b) {
		return ""
	}
	str := string(C.GoBytes(unsafe.Pointer(b.ptr), cint(b.len)))
	C.free_rcstring(b)
	return str
}

func errorWithMessage(err error, b C.RCString) error {
	msg := copyAndDestroyRCString(b)
	if msg == nil {
		fmt.Println("errorWithMessage: msg is nil")
		return err
	}
	return fmt.Errorf("%s", string(msg))
}

func freeCString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

// according to https://pkg.go.dev/unsafe#Pointer case 6.
// StringHeader is valid to interprete the content of an actual string value
func intoRCString(s string) C.RCString {
	p := (*reflect.StringHeader)(unsafe.Pointer(&s))

	return C.RCString{
		ptr: cu8ptr(unsafe.Pointer(p.Data)),
		len: cusize(p.Len),
		cap: cusize(p.Len),
	}
}

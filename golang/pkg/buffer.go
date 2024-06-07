package pkg

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release/ -lobjectscale_client_go -Wl,-rpath,${SRCDIR}/../../target/release/
#include "objectscale_client.h"
*/
import "C"
import (
	"fmt"
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

func copyAndDestroyBuffer(b C.Buffer) []byte {
	if emptyBuffer(b) {
		return nil
	}
	res := C.GoBytes(unsafe.Pointer(b.ptr), cint(b.len))
	C.free_buffer(b)
	return res
}

func emptyBuffer(b C.Buffer) bool {
	return b.ptr == cu8ptr(nil) || b.len == usize(0) || b.cap == usize(0)
}

func errorWithMessage(err error, b C.Buffer) error {
	msg := copyAndDestroyBuffer(b)
	if msg == nil {
		return err
	}
	return fmt.Errorf("%s", string(msg))
}

func freeCString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

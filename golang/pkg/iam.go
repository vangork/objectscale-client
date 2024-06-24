package pkg

// #include "objectscale_client.h"
import "C"

import (
	"runtime"
	"unsafe"
)

// default value for struct fields
// https://stackoverflow.com/a/28625828
type Account struct {
	AccountId         string
	Objscale          string
	CreateDate        string
	EncryptionEnabled bool
	accountDisabled   bool
	Alias             string
	Description       string
	ProtectionEnabled bool
	TsoId             string
	Tags              []Tag
}

func fromCAccount(caccount *C.CAccount) *Account {
	account := Account{
		AccountId:         fromRCString(caccount.account_id),
		Objscale:          fromRCString(caccount.objscale),
		CreateDate:        fromRCString(caccount.create_date),
		EncryptionEnabled: bool(caccount.encryption_enabled),
		accountDisabled:   bool(caccount.account_disabled),
		Alias:             fromRCString(caccount.alias),
		Description:       fromRCString(caccount.description),
		ProtectionEnabled: bool(caccount.protection_enabled),
		TsoId:             fromRCString(caccount.tso_id),
		Tags:              fromRCArrayCTag(caccount.tags),
	}
	C.destroy_caccount(caccount)
	return &account
}

func intoCAccount(account *Account) (*C.CAccount, runtime.Pinner) {
	tags, p1 := intoRCArrayCTag(account.Tags)
	caccount := C.CAccount{
		account_id:         intoRCString(account.AccountId),
		objscale:           intoRCString(account.Objscale),
		create_date:        intoRCString(account.CreateDate),
		encryption_enabled: cbool(account.EncryptionEnabled),
		account_disabled:   cbool(account.accountDisabled),
		alias:              intoRCString(account.Alias),
		description:        intoRCString(account.Description),
		protection_enabled: cbool(account.ProtectionEnabled),
		tso_id:             intoRCString(account.TsoId),
		tags:               tags,
	}
	return &caccount, p1
}

type Tag struct {
	Key   string
	Value string
}

func fromCTag(ctag *C.CTag, destroy bool) *Tag {
	tag := Tag{
		Key:   fromRCString(ctag.key),
		Value: fromRCString(ctag.value),
	}
	if destroy {
		C.destroy_ctag(ctag)
	}
	return &tag
}

func intoCTag(tag *Tag) *C.CTag {
	ctag := C.CTag{
		key:   intoRCString(tag.Key),
		value: intoRCString(tag.Value),
	}
	return &ctag
}

func fromRCArrayCTag(s C.RCArray_CTag) []Tag {
	tags := make([]Tag, 0, s.len)
	array := (*[1 << 30]C.CTag)(unsafe.Pointer(s.ptr))[:s.len:s.len]
	for i := 0; i < int(s.len); i++ {
		t := fromCTag(&array[i], false)
		tags = append(tags, *t)
	}
	C.free_rcarray_ctag(s)
	return tags
}

func intoRCArrayCTag(tags []Tag) (C.RCArray_CTag, runtime.Pinner) {
	ctags := []C.CTag{}
	for _, t := range tags {
		ctags = append(ctags, *intoCTag(&t))
	}

	var p runtime.Pinner
	p.Pin(&ctags[0])
	s := C.RCArray_CTag{
		ptr: (*C.CTag)(unsafe.Pointer(&ctags[0])),
		len: cusize(len(tags)),
		cap: cusize(len(tags)),
	}
	return s, p
}

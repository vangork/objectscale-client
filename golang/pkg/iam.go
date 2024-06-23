package pkg

// #include "objectscale_client.h"
import "C"

type Tag struct {
	key   string
	value string
}

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

func newAccount(caccount *C.CAccount) *Account {
	account := Account{
		AccountId:         readRCString(caccount.account_id),
		Objscale:          readRCString(caccount.objscale),
		CreateDate:        readRCString(caccount.create_date),
		EncryptionEnabled: bool(caccount.encryption_enabled),
		accountDisabled:   bool(caccount.account_disabled),
		Alias:             readRCString(caccount.alias),
		Description:       readRCString(caccount.description),
		ProtectionEnabled: bool(caccount.protection_enabled),
		TsoId:             readRCString(caccount.tso_id),
	}
	C.destroy_caccount(caccount)
	return &account
}

func newCAccount(account *Account) *C.CAccount {
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
    }
	return &caccount
}

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

type AccountBuilder interface {
	SetAlias(alias string) AccountBuilder
	SetDescription(description string) AccountBuilder
	SetEncryptionEnabled(encryptionEnabled bool) AccountBuilder
	SetTags(tags []Tag) AccountBuilder
	Build() *Account
}

type accountBuilder struct {
	account *Account
}

func NewAccountBuilder() AccountBuilder {
	return &accountBuilder{
		account: &Account{
			Description:       "",
			EncryptionEnabled: false,
			Tags:              make([]Tag, 0),
		},
	}
}

func (b *accountBuilder) SetAlias(alias string) AccountBuilder {
	b.account.Alias = alias
	return b
}

func (b *accountBuilder) SetDescription(description string) AccountBuilder {
	b.account.Description = description
	return b
}

func (b *accountBuilder) SetEncryptionEnabled(encryptionEnabled bool) AccountBuilder {
	b.account.EncryptionEnabled = encryptionEnabled
	return b
}

func (b *accountBuilder) SetTags(tags []Tag) AccountBuilder {
	b.account.Tags = tags
	return b
}

func (b *accountBuilder) Build() *Account {
	return b.account
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
	caccount := C.CAccount{}
	caccount.account_id = intoRCString(account.AccountId)
	caccount.objscale = intoRCString(account.Objscale)
	caccount.create_date = intoRCString(account.CreateDate)
	caccount.encryption_enabled = cbool(account.EncryptionEnabled)
	caccount.account_disabled = cbool(account.accountDisabled)
	caccount.alias = intoRCString(account.Alias)
	caccount.description = intoRCString(account.Description)
	caccount.protection_enabled = cbool(account.ProtectionEnabled)
	caccount.tso_id = intoRCString(account.TsoId)
	return &caccount
}

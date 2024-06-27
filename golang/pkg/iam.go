package pkg

// #include "objectscale_client.h"
import "C"

// default value for struct fields
// https://stackoverflow.com/a/28625828
type Account struct {
	AccountId         string `terraform:"account_id"`
	Objscale          string `terraform:"objscale,"`
	CreateDate        string `terraform:"create_date,"`
	EncryptionEnabled bool   `terraform:"encryption_enabled"`
	AccountDisabled   bool   `terraform:"account_disabled,"`
	Alias             string `terraform:"alias"`
	Description       string `terraform:"description"`
	ProtectionEnabled bool   `terraform:"protection_enabled,"`
	TsoId             string `terraform:"tso_id,"`
	Tags              []Tag  `terraform:"tags"`
}

type Tag struct {
	Key   string `terraform:"key"`
	Value string `terraform:"value"`
}

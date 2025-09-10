package pkg

// #include "objectscale_client.h"
import "C"

// Management users can be assigned to VDC-wide management roles and are not associated with a namespace
type ManagementUser struct {
	// User Id. Required
	UserId string `json:"userId" yaml:"userId" tf:"user_id"`
	// User Password. Required. Updatable
	Password string `json:"password" yaml:"password" tf:"password"`
	// Flag indicating whether management user is System Admin. Default: false. Updatable
	IsSystemAdmin bool `json:"isSystemAdmin" yaml:"isSystemAdmin" tf:"is_system_admin"`
	// Flag indicating whether management user is System Monitor. Default: false. Updatable
	IsSystemMonitor bool `json:"isSystemMonitor" yaml:"isSystemMonitor" tf:"is_system_monitor"`
	// Flag indicating whether management user is Security Admin. Default: false. Updatable
	IsSecurityAdmin bool `json:"isSecurityAdmin" yaml:"isSecurityAdmin" tf:"is_security_admin"`
	// If set to true, its a domain.
	IsExternalGroup bool `json:"is_external_group" yaml:"is_external_group" tf:"is_external_group"`
	// If set to true, the user is locked. No need to set value during creation, by default is false. Updatable, but can only set from `true` to `false`
	IsLocked bool `json:"is_locked" yaml:"is_locked" tf:"is_locked"`
	// Value of last time password changed
	LastTimePasswordChanged string `json:"last_time_password_changed" yaml:"last_time_password_changed" tf:"last_time_password_changed"`
}

// Object users can be assigned to management and object user roles for the namespace.
type ObjectUser struct {
	// User name. Required
	Name string `json:"name" yaml:"user" tf:"name"`
	// Namespace that owns the user. Required
	Namespace string `json:"namespace" yaml:"namespace" tf:"namespace"`
	// Set true if user needs to be is to be locked, false otherwise. Default: false. Updatable
	Locked bool `json:"locked" yaml:"locked" tf:"locked"`
	// Gets the user's creation date as an ISO-8601 timestamp.
	Created string `json:"created" yaml:"created" tf:"created"`
	// The tags associated with this user. Default: []. Updatable
	Tag []UserTag `json:"tag" yaml:"tag" tf:"tag"`
	// Gets the user's centerapassword.
	Centerapassword string `json:"centerapassword" yaml:"centerapassword" tf:"centerapassword"`
	// Gets the user's swiftpassword.
	Swiftpassword string `json:"swiftpassword" yaml:"swiftpassword" tf:"swiftpassword"`
	// Managing Swift passwords and assigning Swift users to groups. Default: see SwiftGroup. Updatable
	SwiftGroup SwiftGroup `json:"swift_group" yaml:"swift_group" tf:"swift_group"`
	// User can access the object store with a secret key. At most two secret keys can be created. Default: []. Updatable
	SecretKeys []SecretKey `json:"secret_keys" yaml:"secret_keys" tf:"secret_keys"`
}

// User can access the object store with a secret key.
type SecretKey struct {
	// Secret key associated with this user.
	SecretKey string `json:"secret_key" yaml:"secret_key" tf:"secret_key"`
	// Expiry time in minutes for the secret key. Empty for no expiry. Default: "".
	ExistingKeyExpiryTimeMins string `json:"existing_key_expiry_time_mins" yaml:"existing_key_expiry_time_mins" tf:"existing_key_expiry_time_mins"`
	// Secret key creation timestamp in ISO-8601 format
	KeyTimestamp string `json:"key_timestamp" yaml:"key_timestamp" tf:"key_timestamp"`
	// Secret key expiry timestamp in ISO-8601 format
	KeyExpiryTimestamp string `json:"key_expiry_timestamp" yaml:"key_expiry_timestamp" tf:"key_expiry_timestamp"`
	// SHA-256 hash of Secret key
	SecretKeyId string `json:"secret_key_id" yaml:"secret_key_id" tf:"secret_key_id"`
}

// Managing Swift passwords and assigning Swift users to groups.
type SwiftGroup struct {
	// Password for the user. Empty for no password and group. Default: "". Updatable
	Password string `json:"password" yaml:"password" tf:"password"`
	// List of ADMIN groups for the user. Empty for no password and group. Default: []. Updatable
	GroupsList []string `json:"groups_list" yaml:"groups_list" tf:"groups_list"`
	// Swift password configured.
	SwiftPasswordConfigured bool `json:"swift_password_configured" yaml:"swift_password_configured" tf:"swift_password_configured"`
}

// Lables for Object User.
type UserTag struct {
	// The name of a tag.
	Name string `json:"name" yaml:"name" tf:"name"`
	// The value of a tag.
	Value string `json:"value" yaml:"value" tf:"value"`
}

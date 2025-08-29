package pkg

// #include "objectscale_client.h"
import "C"

// Management users can be assigned to VDC-wide management roles and are not associated with a namespace
type ManagementUser struct {
	// User Id. Required
	UserId string `json:"userId" yaml:"userId"`
	// User Password. Required. Updatable
	Password string `json:"password" yaml:"password"`
	// Flag indicating whether management user is System Admin. Default: false. Updatable
	IsSystemAdmin bool `json:"isSystemAdmin" yaml:"isSystemAdmin"`
	// Flag indicating whether management user is System Monitor. Default: false. Updatable
	IsSystemMonitor bool `json:"isSystemMonitor" yaml:"isSystemMonitor"`
	// Flag indicating whether management user is Security Admin. Default: false. Updatable
	IsSecurityAdmin bool `json:"isSecurityAdmin" yaml:"isSecurityAdmin"`
	// If set to true, its a domain.
	IsExternalGroup bool `json:"is_external_group" yaml:"is_external_group"`
	// If set to true, the user is locked. Updatable, but can only set from `true` to `false`
	IsLocked bool `json:"is_locked" yaml:"is_locked"`
	// Value of last time password changed
	LastTimePasswordChanged string `json:"last_time_password_changed" yaml:"last_time_password_changed"`
}

// Object users can be assigned to management and object user roles for the namespace.
type ObjectUser struct {
	// User name. Required
	Name string `json:"name" yaml:"user"`
	// Namespace that owns the user. Required
	Namespace string `json:"namespace" yaml:"namespace"`
	// Set true if user needs to be is to be locked, false otherwise. Updatable
	Locked bool `json:"locked" yaml:"locked"`
	// Gets the user's creation date as an ISO-8601 timestamp.
	Created string `json:"created" yaml:"created"`
	// The tags associated with this user. Updatable
	Tag []UserTag `json:"tag" yaml:"tag"`
	// Gets the user's centerapassword.
	Centerapassword string `json:"centerapassword" yaml:"centerapassword"`
	// Gets the user's swiftpassword.
	Swiftpassword string `json:"swiftpassword" yaml:"swiftpassword"`
}

// Lables for Object User.
type UserTag struct {
	// The name of a tag.
	Name string `json:"name" yaml:"name"`
	// The value of a tag.
	Value string `json:"value" yaml:"value"`
}

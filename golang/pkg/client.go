package pkg

// #include "objectscale_client.h"
import "C"

// Client is responsible for ObjectScale management
type Client struct {
	client *C.Client
}

type Account struct {
	AccountId string
}

func NewAccount(iamAccount *C.CAccount) *Account {
	acccount := Account{
		AccountId: readRCString(iamAccount.account_id),
	}
	C.destroy_caccount(iamAccount)
	return &acccount
}

// Create a OjectScale client.
// E.g. client, err := NewAPIClient(config)
func NewClient(endpoint string, username string, password string, insecure bool) (*Client, error) {
	msg := C.RCString{}
	cEndpoint := C.CString(endpoint)
	cUsername := C.CString(username)
	cPassword := C.CString(password)
	cInsecure := cbool(insecure)
	client, err := C.new_client(cEndpoint, cUsername, cPassword, cInsecure, &msg)
	freeCString(cEndpoint)
	freeCString(cUsername)
	freeCString(cPassword)

	if err != nil {
		return nil, errorWithMessage(err, msg)
	}
	return &Client{
		client,
	}, nil
}

// Close the APIClient.
// Make sure to call this function when you are done using the client.
func (client *Client) Close() {
	C.destroy_client(client.client)
}

// Create account with a given alias.
func (client *Client) CreateAccount(alias string) (*Account, error) {
	msg := C.RCString{}
	cAlias := C.CString(alias)
	cAccount, err := C.client_create_account(client.client, cAlias, &msg)
	freeCString(cAlias)
	if err != nil {
		return nil, errorWithMessage(err, msg)
	}
	account := NewAccount(cAccount)
	return account, nil
}

// Delete account with a given id.
func (client *Client) DeleteAccount(id string) error {
	msg := C.RCString{}
	cId := C.CString(id)
	_, err := C.client_delete_account(client.client, cId, &msg)
	freeCString(cId)
	if err != nil {
		return errorWithMessage(err, msg)
	}
	return nil
}

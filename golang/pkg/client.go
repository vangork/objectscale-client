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

func NewAccount(iamAccount *C.IamAccount) *Account {
	id := C.GoString(iamAccount.account_id)
	C.free_string(iamAccount.account_id)

	C.iam_account_destroy(iamAccount)

	acccount := Account{
		AccountId: string(id),
	}

	return &acccount
}

// Create a OjectScale client.
// E.g.
//
//	client, err := NewAPIClient(config)
func NewClient(endpoint string, username string, password string, insecure bool) (*Client, error) {
	msg := C.Buffer{}
	cEndpoint := C.CString(endpoint)
	cUsername := C.CString(username)
	cPassword := C.CString(password)
	cInsecure := cbool(insecure)
	client, err := C.client_new(cEndpoint, cUsername, cPassword, cInsecure, &msg)
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

// Close the APIClient. Stop the reactor goroutine and release the resources
func (client *Client) Close() {
	C.client_destroy(client.client)
}

// Create account with a given alias.
func (client *Client) CreateAccount(alias string) (*Account, error) {
	msg := C.Buffer{}
	cAlias := C.CString(alias)
	iamAccount, err := C.client_create_account(client.client, cAlias, &msg)
	freeCString(cAlias)
	if err != nil {
		return nil, errorWithMessage(err, msg)
	}
	account := NewAccount(iamAccount)
	return account, nil
}

// Delete account with a given id.
func (client *Client) DeleteAccount(id string) error {
	msg := C.Buffer{}
	cId := C.CString(id)
	_, err := C.client_delete_account(client.client, cId, &msg)
	freeCString(cId)
	if err != nil {
		return errorWithMessage(err, msg)
	}
	return nil
}

package pkg

// #include "objectscale_client.h"
import "C"
import "encoding/json"

// Client is responsible for ObjectScale management
type Client struct {
	client *C.Client
}

// Create a OjectScale client.
// E.g. client, err := NewAPIClient(config)
func NewClient(endpoint string, username string, password string, insecure bool) (*Client, error) {
	msg := C.RCString{}
	cEndpoint := intoRCString(endpoint)
	cUsername := intoRCString(username)
	cPassword := intoRCString(password)
	cInsecure := cbool(insecure)
	client, err := C.new_client(cEndpoint, cUsername, cPassword, cInsecure, &msg)

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

// Create account with a given account.
func (client *Client) CreateAccount(account *Account) (*Account, error) {
	msg := C.RCString{}
	bytes, err := json.Marshal(account)
	if err != nil {
		return nil, err
	}
	cAccount := intoRCString(string(bytes))
	cAccount, err = C.client_create_account(client.client, cAccount, &msg)
	if err != nil {
		return nil, errorWithMessage(err, msg)
	}
	accountJson := fromRCString(cAccount)
	var newAccount Account
	err = json.Unmarshal([]byte(accountJson), &newAccount)
	if err != nil {
		return nil, err
	}
	return &newAccount, nil
}

// Get account with a given id.
func (client *Client) GetAccount(id string) (*Account, error) {
	msg := C.RCString{}
	cId := intoRCString(id)
	cAccount, err := C.client_get_account(client.client, cId, &msg)
	if err != nil {
		return nil, errorWithMessage(err, msg)
	}
	accountJson := fromRCString(cAccount)
	var account Account
	err = json.Unmarshal([]byte(accountJson), &account)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// Delete account with a given id.
func (client *Client) DeleteAccount(id string) error {
	msg := C.RCString{}
	cId := intoRCString(id)
	_, err := C.client_delete_account(client.client, cId, &msg)
	if err != nil {
		return errorWithMessage(err, msg)
	}
	return nil
}

// List accounts.
func (client *Client) ListAccounts() ([]Account, error) {
	msg := C.RCString{}
	cAccounts, err := C.client_list_accounts(client.client, &msg)
	if err != nil {
		return nil, errorWithMessage(err, msg)
	}
	accountsJson := fromRCString(cAccounts)
	var accounts []Account
	err = json.Unmarshal([]byte(accountsJson), &accounts)
	if err != nil {
		return nil, err
	}
	return accounts, nil
}

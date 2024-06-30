package pkg

// #include "objectscale_client.h"
import "C"
import "encoding/json"


// This class definition creates a new instance of the Client struct with a pointer to a C.Client.
// The Client struct is used to interact with the ObjectScale API.
type Client struct {
	client *C.Client
}

// NewClient creates a new instance of the Client struct with a pointer to a C.Client.
// The Client struct is used to interact with the ObjectScale API.
//
// Parameters:
// - endpoint: The endpoint of the ObjectScale API.
// - username: The username for authentication.
// - password: The password for authentication.
// - insecure: Whether to use insecure HTTPS connections.
//
// Returns:
// - *Client: A pointer to the newly created Client instance.
// - error: An error if any occurred.
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

// CreateAccount creates a new account with the given account details.
// Returns the newly created account and an error if any occurred.
//
// Parameters:
// - account: The account details to create a new account.
//
// Returns:
// - *Account: The newly created account.
// - error: An error if any occurred.
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

// GetAccount retrieves an account with the given ID.
//
// Parameters:
// - id: The account Id.
// - ...
//
// Returns:
// - *Account: The retrieved account.
// - error: An error if the account retrieval fails.
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

// DeleteAccount deletes an account with the given ID.
//
// Parameters:
// - id: The account Id.
// - ...
//
// Returns:
// - error: An error if the account deletion fails.
func (client *Client) DeleteAccount(id string) error {
	msg := C.RCString{}
	cId := intoRCString(id)
	_, err := C.client_delete_account(client.client, cId, &msg)
	if err != nil {
		return errorWithMessage(err, msg)
	}
	return nil
}

// UpdateAccount updates the account with the given details.
//
// Parameters:
// - account: A pointer to the Account object containing the updated details.
//
// Returns:
// - *Account: The updated Account object.
// - error: An error if the update fails.
func (client *Client) UpdateAccount(account *Account) (*Account, error) {
	return account, nil
}

// ListAccounts lists the accounts.
//
// Parameters:
// - ...

// Returns:
// - []Account: A slice of accounts.
// - error: An error if the account retrieval fails.
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

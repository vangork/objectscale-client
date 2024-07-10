package pkg

// #include "objectscale_client.h"
import "C"
import "encoding/json"

// This class definition creates a new instance of the Client struct with a pointer to a C.Client.
// The Client struct is used to interact with the ObjectScale API.
type ManagementClient struct {
	managementClient *C.ManagementClient
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
func NewManagementClient(endpoint string, username string, password string, insecure bool) (*ManagementClient, error) {
	msg := C.RCString{}
	cEndpoint := intoRCString(endpoint)
	cUsername := intoRCString(username)
	cPassword := intoRCString(password)
	cInsecure := cbool(insecure)
	managementClient, err := C.new_management_client(cEndpoint, cUsername, cPassword, cInsecure, &msg)

	if err != nil {
		return nil, errorWithMessage(err, msg)
	}
	return &ManagementClient{
		managementClient,
	}, nil
}

// Close the APIClient.
// Make sure to call this function when you are done using the client.
func (managementClient *ManagementClient) Close() {
	C.destroy_management_client(managementClient.managementClient)
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
func (managementClient *ManagementClient) CreateAccount(account *Account) (*Account, error) {
	msg := C.RCString{}
	bytes, err := json.Marshal(account)
	if err != nil {
		return nil, err
	}
	cAccount := intoRCString(string(bytes))
	cAccount, err = C.management_client_create_account(managementClient.managementClient, cAccount, &msg)
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
func (managementClient *ManagementClient) GetAccount(id string) (*Account, error) {
	msg := C.RCString{}
	cId := intoRCString(id)
	cAccount, err := C.management_client_get_account(managementClient.managementClient, cId, &msg)
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
func (managementClient *ManagementClient) DeleteAccount(id string) error {
	msg := C.RCString{}
	cId := intoRCString(id)
	_, err := C.management_client_delete_account(managementClient.managementClient, cId, &msg)
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
func (managementClient *ManagementClient) UpdateAccount(account *Account) (*Account, error) {
	return account, nil
}

// ListAccounts lists the accounts.
//
// Parameters:
// - ...

// Returns:
// - []Account: A slice of accounts.
// - error: An error if the account retrieval fails.
func (managementClient *ManagementClient) ListAccounts() ([]Account, error) {
	msg := C.RCString{}
	cAccounts, err := C.management_client_list_accounts(managementClient.managementClient, &msg)
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

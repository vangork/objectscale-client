import objectscale_client
import pprint

def main():
    endpoint = "https://10.225.108.189:443"
    username = "root"
    password = "Password123@"
    insecure = True

    alias = "test"

    client = objectscale_client.ManagementClient(endpoint, username, password, insecure)
    account = objectscale_client.Account()
    account.alias = alias

    try:
        new_account = client.create_account(account)
        print("Created account:", new_account.account_id)
    except Exception as e:
        print("Failed to create account:", e)


if __name__ == '__main__':
    main()

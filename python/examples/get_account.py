import objectscale_client

def main():
    endpoint = "https://10.225.108.189:443"
    username = "root"
    password = "Password123@"
    insecure = True

    account_id = "osai0a9250592a131336"

    try:
        client = objectscale_client.client.ManagementClient(endpoint, username, password, insecure)
        account = client.get_account(account_id)
        print("Get account:", account)
    except Exception as e:
        print("Failed to get account:", e)


if __name__ == '__main__':
    main()

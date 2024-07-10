import objectscale_client

def main():
    endpoint = "https://10.225.108.189:443"
    username = "root"
    password = "Password123@"
    insecure = True

    client = objectscale_client.ManagementClient(endpoint, username, password, insecure)

    try:
        accounts = client.list_accounts()
        for account in accounts:
            print(account)
    except Exception as e:
        print("Failed to list accounts:", e)


if __name__ == '__main__':
    main()

import objectscale_client
import pprint

endpoint = "https://10.225.108.186:443"
username = "root"
password = "Password123@"
insecure = True

alias = "test"

client = objectscale_client.Client(endpoint, username, password, insecure)

try:
    account = client.create_account(alias)
    print("Created account:", account.account_id)
except Exception as e:
    print("Failed to create account:", e)

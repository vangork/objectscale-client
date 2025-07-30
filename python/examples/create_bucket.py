import objectscale_client

def main():
    endpoint = "https://10.225.108.217:4443"
    username = "root"
    password = "Password123!"
    insecure = True

    bucket = objectscale_client.bucket.Bucket()
    bucket.name = "luis_bucket"
    bucket.namespace = "ns1"
    
    tag = objectscale_client.bucket.BucketTag()
    tag.key = "key1"
    tag.value = "value1"
    bucket.tags = [tag]

    meta_data1 = objectscale_client.bucket.MetaData()
    meta_data1.datatype = "datetime"
    meta_data1.name = "CreateTime"
    meta_data1.type = "System"

    meta_data2 = objectscale_client.bucket.MetaData()
    meta_data2.datatype = "integer"
    meta_data2.name = "x-amz-meta-size"
    meta_data2.type = "User"

    search_metadata = objectscale_client.bucket.SearchMetaData()
    search_metadata.metadata = [meta_data1, meta_data2]
    bucket.search_metadata = search_metadata

    try:
        client = objectscale_client.client.ManagementClient(endpoint, username, password, insecure)
        new_bucket = client.create_bucket(bucket)
        print("Created bucket:", new_bucket)
    except Exception as e:
        print("Failed to create bucket:", e)


if __name__ == '__main__':
    main()

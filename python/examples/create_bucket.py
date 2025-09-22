#
# Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

import objectscale_client

def main():
    endpoint = "https://10.225.108.217:4443"
    username = "root"
    password = "Password123!"
    insecure = True

    bucket = objectscale_client.provisioning.Bucket()
    bucket.name = "luis_bucket"
    bucket.namespace = "ns1"
    bucket.block_size = -1
    bucket.notification_size = -1
    bucket.block_size_in_count = -1
    bucket.notification_size_in_count = -1
    bucket.audit_delete_expiration = -2
    
    tag = objectscale_client.provisioning.BucketTag()
    tag.key = "key1"
    tag.value = "value1"
    bucket.tags = [tag]

    meta_data1 = objectscale_client.provisioning.MetaData()
    meta_data1.datatype = "datetime"
    meta_data1.name = "CreateTime"
    meta_data1.type = "System"

    meta_data2 = objectscale_client.provisioning.MetaData()
    meta_data2.datatype = "integer"
    meta_data2.name = "x-amz-meta-size"
    meta_data2.type = "User"

    search_metadata = objectscale_client.provisioning.SearchMetaData()
    search_metadata.metadata = [meta_data1, meta_data2]
    search_metadata.is_enabled = True
    bucket.search_metadata = search_metadata

    try:
        client = objectscale_client.client.ManagementClient(endpoint, username, password, insecure)
        new_bucket = client.create_bucket(bucket)
        print("Created bucket:", new_bucket)
    except Exception as e:
        print("Failed to create bucket:", e)


if __name__ == '__main__':
    main()

## AssumeRoleWithClientGrants
Returns a set of temporary security credentials for applications/clients who have been authenticated through client grants provided by your identity provider. Example providers include WSO2, KeyCloack etc.

Calling AssumeRoleWithClientGrants does not require the use of Minio default credentials. Therefore, you can distribute an application that requests temporary security credentials without including Minio default credentials in the application. Instead, the identity of the caller is validated by using a JWT access token from the identity provider. The temporary security credentials returned by this API consist of an access key, a secret key, and a security token. Applications can use these temporary security credentials to sign calls to Minio API operations.

By default, the temporary security credentials created by AssumeRoleWithClientGrants last for one hour. However, you can use the optional DurationSeconds parameter to specify the duration of your session. You can provide a value from 900 seconds (15 minutes) up to the maximum session duration to 12 hours.

### Request Parameters

#### DurationSeconds
The duration, in seconds. The value can range from 900 seconds (15 minutes) up to the 12 hours. If you specify a value higher than this setting, the operation fails. By default, the value is set to 3600 seconds.

| Params | Value |
| :-- | :-- |
| *Type* | *Integer* |
| *Valid Range* | *Minimum value of 900. Maximum value of 43200.* |
| *Required* | *No* |

#### Token
The OAuth 2.0 access token that is provided by the identity provider. Your application must get this token by authenticating the application using client grants before the application makes an AssumeRoleWithClientGrants call.

| Params | Value |
| :-- | :-- |
| *Type* | *String* |
| *Length Constraints* | *Minimum length of 4. Maximum length of 2048.* |
| *Required* | *Yes* |

#### Response Elements
XML response for this API is similar to [AWS STS AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html#API_AssumeRoleWithWebIdentity_ResponseElements)

#### Errors
XML error response for this API is similar to [AWS STS AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html#API_AssumeRoleWithWebIdentity_Errors)

#### Testing
Start Minio server with etcd configured, please follow installation guide here [etcd](https://coreos.com/etcd/docs/latest/). Minio STS feature requires etcdv3 server running.
```
$ export MINIO_ACCESS_KEY=minio
$ export MINIO_SECRET_KEY=minio123
$ export MINIO_ETCD_ENDPOINTS=http://127.0.0.1:2379
$ minio server /mnt/export

$ ETCDCTL_API=3 etcdctl get /home/$(id -u -n)/.minio/config.json --print-value-only > new-config.json

... edit new-config.json with following entries ...

    "auth": {
		"jwt": {
			"enable": true,
			"jwksURL": "https://localhost:9443/oauth2/jwks"
		}
	},
    "access": {
        "opa": {
            "url": "http://localhost:8181/v1/data/httpapi/authz",
            "authToken": ""
        }
    }

$ cat new-config.json | etcdctl put /home/$(id -u -n)/.minio/config.json
```

Testing with an example
> Obtaining JWT access token follow your identity providers documentation.

```
$ go run sts-example.go -ep http://localhost:9000 -t "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJQb0VnWFA2dVZPNDVJc0VOUm5nRFhqNUF1NVlhIiwiYXpwIjoiUG9FZ1hQNnVWTzQ1SXNFTlJuZ0RYajVBdTVZYSIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTUzMjUxNTk2MSwiaWF0IjoxNTMyNTEyMzYxLCJqdGkiOiJlYzUyZTg3OS00ZTBiLTQzMWQtODA1Mi1jYjQ5NjFmMWJmZjkifQ.fNh2yH9n1KQwFUYYQcHtrianT_5_S_asFKlxxy_ZToqwCW0_b37jNaKNDXAjR17-DEZPExxJO7UaY2XIJjLgUT5Xda9AOw9yQMVcFRXHqIKSM0qgOBHE3YdC2RId4tDJiKfynhqBM9-IbA6D4olLHHy4Hjd09CRHeAHDZSHEIYfRjhzBaGT_cH9LaFphXrCHfC6e2h6gYy_g4wS67SOf7Z-7nEdulKkRtsaKiCYmi3N0tdbb2YsNX5TEPclgmuVeHRvYeuaGUZXuEDGXUVHR8_ewm_TuYm6iAkjsYsGJ0zvSQK2wZl4qKDcAojNijV_VtEOyOHpzxHQ1WuxEOR79hQ"
```

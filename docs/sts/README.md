## Minio STS
The Minio Security Token Service (STS) is an endpoint service that enables you to request temporary credentials for your Minio resources. Temporary credentials work almost identically to your default admin credentials, with some differences:

- Temporary credentials are short-term, as the name implies. They can be configured to last for anywhere from a few minutes to several hours. After the credentials expire, Minio no longer recognizes them or allows any kind of access from API requests made with them.
- Temporary credentials do not need to be stored with the application but are generated dynamically and provided to the application when requested. When (or even before) the temporary credentials expire, the application can request new credentials.

Following are advantages for using temporary credentials:

- You do not have to embed long-term admin credentials with an application.
- You can provide access to buckets and objects without having to define static credentials.
- Temporary credentials have a limited lifetime, so you do not have to rotate them or explicitly revoke them when they're no longer needed. After temporary credentials expire, they cannot be reused.

### Identity Federation

- [**Client grants**](./client-grants.md) - You can let users sign in using a well-known third party identity provider such as WSO2, Keycloak. You can exchange the credentials from that provider for temporary permissions for Minio API. This is known as the client grants approach to temporary access. Using this approach helps you keep your Minio secure, because you don't have to distribute admin credentials. Minio STS client grants supports WSO2, Keycloak.

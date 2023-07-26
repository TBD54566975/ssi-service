# Storage

The SSI Service supports multiple storage technologies. All storage operations are abstracted away by an interface. The
interface is based was designed as a Key Value store that supports optimistic concurrency. We provide implementations
out of the box for Redis, SQL, and Bolt.

## Choosing Implementations

### Redis

You can configure SSI service to use Redis by setting the following options in your TOML configuration.

```toml
[services]
storage = "redis"

[[services.storage_option]]
id = "redis-address-option"
option = "redis:6379"

[[services.storage_option]]
id = "storage-password-option"
option = "password"
```

For a working example, see this [prod.toml file](https://github.com/TBD54566975/ssi-service/blob/85fb66cc2ddfd33e3c33174710fe5a78a7a5ee7f/config/prod.toml#L28-L36)

Depending on your data needs, you may want to choose different Redis persistence strategies. For the most durable and
disaster recovery ready alternative, please make sure to turn on RBD + AOF, with AOF doing an fsync for every write. 
More details are available in the [Redis Persistence](https://redis.io/docs/management/persistence/) page.

### SQL

You can configure SSI service to use any `database/sql` driver by setting the following options in your TOML configuration.

```toml
[services]
storage = "database_sql"

[[services.storage_option]]
id = "sql-connection-string-option"
option = "host=localhost port=5432 user=postgres password=postgres dbname=postgres sslmode=disable"

[[services.storage_option]]
id = "sql-driver-name-option"
option = "postgres"
```

#### Limitations

SSI-service's SQL implementation includes the `github.com/lib/pq` driver for PostgreSQL. If you need to support for an
additional driver, please open a PR.

### Bolt

You can configure it by setting the following options in your TOML configuration.

```toml
[services]
storage = "bolt"

[[services.storage_option]]
id = "boltdb-filepath-option"
option = "bolt.db"
```

For a working example, see this [dev.toml file](https://github.com/TBD54566975/ssi-service/blob/85fb66cc2ddfd33e3c33174710fe5a78a7a5ee7f/config/dev.toml#L29-L34)

## Implementing a New Storage Provider

You need to implement the [ServiceStorage interface](../pkg/storage/storage.go), similar to how [Redis](../pkg/storage/redis.go)
is implemented. For an example, see [this PR](https://github.com/TBD54566975/ssi-service/pull/590/files#diff-606358579107e7ad1221525001aed8c776a141d4cc5aab9ef7a3ddbcec10d9f9)
which introduces the SQL based implementation.

## Encryption

SSI Service supports application level encryption of values before sending them to the configured KV store. Please note
that keys (i.e. the key of the KV store) are not currently encrypted. See the [Privacy Considerations](#privacy-considerations) for more information.
A MasterKey is used (a.k.a. a Data Encryption Key or DEK) to encrypt all data before it's sent to the configured storage.
The MasterKey can be stored in the configured storage system or in an external Key Management System (KMS) like GCP KMS or AWS KMS.
When storing locally, the key will be automatically generated if it doesn't exist already.

**For production deployments, it is strongly recommended to store the MasterKey in an external KMS.**

To use an external KMS:
1. Create a symmetric encryption key in your KMS. You MUST select the algorithm that uses AES-256 block cipher in Galois/Counter Mode (GCM). At the time of writing, this is the only algorithm supported by AWS and GCP.
2. Set the `master_key_uri` field of the `[services.storage_encryption]` section using the format described in [tink](https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#key-management-systems)
   (we use the tink library under the hood).
3. Set the `kms_credentials_path` field of the `[services.storage_encryption]` section to point to your credentials file, according to [this section](https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#credentials).
4. Win!

Below, there is an example snippet of what the TOML configuration should look like.
```toml
[services.storage_encryption]
# Make sure the following values are valid.
master_key_uri = "gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*"
kms_credentials_path = "credentials.json"
disable_encryption = false
```

Storing the MasterKey in the configured storage system is done with the following options in your TOML configuration.

```toml
[services.storage_encryption]
# ensure that master_key_uri is NOT set.
disable_encryption = false
```

Disabling app level encryption is also possible using the following options in your TOML configuration:

```toml
[services.storage_encryption]
# encryption
disable_encryption = true
```

### Privacy Considerations

From the perspective of SSI-Service, all keys are stored in plaintext (this doesn't preclude configuring encryption at rest
in your deployment of the storage configuration). Making all keys readable by any actor may have an impact in your organization's
use cases around privacy. You should consider whether this is acceptable. Notably, a DID that was created by SSI Service
is stored as a key. This can fit some definition of PII, as it could be correlated to identify and individual.

Encrypting keys is being considered in https://github.com/TBD54566975/ssi-service/issues/603.
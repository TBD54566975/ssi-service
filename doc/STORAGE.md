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
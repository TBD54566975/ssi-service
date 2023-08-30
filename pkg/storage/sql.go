package storage

import (
	"context"
	"database/sql"
	"encoding/base64"

	// We include the postresql driver in our implementation, so users can pick "postgres" via configuration.
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func init() {
	if err := RegisterStorage(new(SQLDB)); err != nil {
		panic(err)
	}
}

const (
	SQLConnectionString OptionKey = "sql-connection-string-option"
	SQLDriverName       OptionKey = "sql-driver-name-option"
)

type SQLDB struct {
	db               *sql.DB
	connectionString string
}

func (s *SQLDB) Init(opts ...Option) error {
	connString, sqlDriverName, err := processSQLOptions(opts...)
	if err != nil {
		return err
	}
	s.connectionString = connString

	db, err := sql.Open(sqlDriverName, connString)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS key_values (
    key varchar,
    value varchar
);`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE INDEX idx_key_values ON key_values USING hash (key);`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS namespaces (
    namespace varchar
);`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE INDEX idx_namespaces ON namespaces USING hash (namespace);`)
	if err != nil {
		return err
	}

	s.db = db
	return nil
}

func processSQLOptions(opts ...Option) (connString string, sqlDriverName string, err error) {
	if len(opts) != 2 {
		return "", "", errors.New("sql options must contain connection string and driver name")
	}
	for _, opt := range opts {
		switch opt.ID {
		case SQLConnectionString:
			maybeConnString, ok := opt.Option.(string)
			if !ok {
				err = errors.New("sql connection string must be a string")
				return
			}
			if len(maybeConnString) == 0 {
				err = errors.New("sql connection string must not be empty")
				return
			}
			connString = maybeConnString
		case SQLDriverName:
			maybeDriverName, ok := opt.Option.(string)
			if !ok {
				err = errors.New("sql driver name must be a string")
				return
			}
			if len(maybeDriverName) == 0 {
				err = errors.New("sql driver name must not be empty")
				return
			}
			sqlDriverName = maybeDriverName
		}
	}
	if len(connString) == 0 || len(sqlDriverName) == 0 {
		err = errors.New("sql connection string and driver name must not be empty")
		return
	}
	return connString, sqlDriverName, nil
}

func (s *SQLDB) Type() Type {
	return DatabaseSQL
}

func (s *SQLDB) URI() string {
	return s.connectionString
}

func (s *SQLDB) IsOpen() bool {
	err := s.db.Ping()
	if err != nil {
		logrus.WithError(err).Error("pinging db")
		return false
	}
	return true
}

func (s *SQLDB) Close() error {
	return s.db.Close()
}

func (s *SQLDB) Write(ctx context.Context, namespace, key string, value []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {
			logrus.WithError(err).Error("unable to rollback")
		}
	}(tx)

	if err := write(ctx, tx, namespace, key, value); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "committing transaction")
	}
	return nil
}

type ExecContext interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func write(ctx context.Context, db ExecContext, namespace, key string, value []byte) error {
	_, err := db.ExecContext(ctx, "INSERT INTO namespaces (namespace) VALUES ($1) EXCEPT SELECT namespace FROM namespaces WHERE namespace = $2", namespace, namespace)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "INSERT INTO key_values (key, value) VALUES ($1, $2)", Join(namespace, key), base64.RawStdEncoding.EncodeToString(value))
	return err
}

func (s *SQLDB) WriteMany(ctx context.Context, namespaces, keys []string, values [][]byte) error {
	stmt, err := s.db.Prepare("INSERT INTO key_values (key, value) VALUES ($1, $2)")
	if err != nil {
		return err
	}
	defer func(stmt *sql.Stmt) {
		_ = stmt.Close()
	}(stmt)

	for i, k := range keys {
		_, err = stmt.ExecContext(ctx, Join(namespaces[i], k), base64.RawStdEncoding.EncodeToString(values[i]))
		if err != nil {
			return err
		}
	}
	return err
}

func (s *SQLDB) Read(ctx context.Context, namespace, key string) ([]byte, error) {
	return read(ctx, s.db, namespace, key)
}

type QueryRow interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func read(ctx context.Context, db QueryRow, namespace, key string) ([]byte, error) {
	r := db.QueryRowContext(ctx, "SELECT value FROM key_values WHERE key = $1", Join(namespace, key))
	var value string
	err := r.Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func (s *SQLDB) Exists(ctx context.Context, namespace, key string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM key_values
			WHERE key = $1
			LIMIT 1
		)
	`

	// Execute the query and retrieve the result
	var exists bool
	err := s.db.QueryRowContext(ctx, query, Join(namespace, key)).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (s *SQLDB) ReadAll(ctx context.Context, namespace string) (map[string][]byte, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM key_values WHERE key LIKE $1", Join(namespace, "%"))
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			logrus.WithError(err).Error("closing rows")
		}
	}(rows)

	allValues, _, err := readRowsAsMap(rows, namespace)
	return allValues, err
}

func readRowsAsMap(rows *sql.Rows, namespace string) (map[string][]byte, string, error) {
	allValues := make(map[string][]byte)
	var mapKey string
	for rows.Next() {
		var key string
		var value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, "", err
		}
		mapKey = key[len(namespace)+1:]
		decoded, err := base64.RawStdEncoding.DecodeString(value)
		if err != nil {
			return nil, "", err
		}
		allValues[mapKey] = decoded
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return allValues, mapKey, nil
}

func (s *SQLDB) ReadPage(ctx context.Context, namespace string, pageToken string, pageSize int) (results map[string][]byte, nextPageToken string, err error) {
	var rows *sql.Rows
	if pageSize == -1 {
		rows, err = s.db.QueryContext(ctx, "SELECT * FROM key_values WHERE key LIKE $1 AND key >= $2 ORDER BY key", Join(namespace, "%"), pageToken)
	} else {
		rows, err = s.db.QueryContext(ctx, "SELECT * FROM key_values WHERE key LIKE $1 AND key >= $2 ORDER BY key LIMIT $3", Join(namespace, "%"), pageToken, pageSize+1)
	}
	if err != nil {

		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", nil
		}
		return nil, "", err
	}
	pageValues, lastMapKey, err := readRowsAsMap(rows, namespace)
	if err != nil {
		return nil, "", err
	}
	if pageSize == -1 {
		nextPageToken = ""
	} else {
		if len(pageValues) <= pageSize {
			nextPageToken = ""
		} else {
			nextPageToken = Join(namespace, lastMapKey)
			delete(pageValues, lastMapKey)
		}
	}
	return pageValues, nextPageToken, nil
}

func (s *SQLDB) ReadPrefix(ctx context.Context, namespace, prefix string) (map[string][]byte, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM key_values WHERE key LIKE $1", Join(namespace, prefix)+"%")
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			logrus.WithError(err).Error("closing rows")
		}
	}(rows)

	allValues, _, err := readRowsAsMap(rows, namespace)
	return allValues, err
}

func (s *SQLDB) ReadAllKeys(ctx context.Context, namespace string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key FROM key_values WHERE key LIKE $1", Join(namespace, "%"))
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			logrus.WithError(err).Error("closing rows")
		}
	}(rows)

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key[len(namespace)+1:])
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, err
}

func (s *SQLDB) Delete(ctx context.Context, namespace, key string) error {
	row := s.db.QueryRowContext(ctx, "SELECT * FROM namespaces WHERE namespace = $1", namespace)
	var gotNamespace string
	if err := row.Scan(&gotNamespace); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.Errorf("namespace<%s> does not exist", namespace)
		}
		return err
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM key_values WHERE key = $1", Join(namespace, key))
	if err != nil {
		return err
	}
	return nil
}

func (s *SQLDB) DeleteNamespace(ctx context.Context, namespace string) error {
	row := s.db.QueryRowContext(ctx, "DELETE FROM namespaces WHERE namespace = $1 RETURNING *", namespace)
	var namespaceRemoved string
	if err := row.Scan(&namespaceRemoved); err != nil {
		return errors.Wrap(err, "deleting namespace<bad>")
	}

	_, err := s.db.ExecContext(ctx, "DELETE FROM key_values WHERE key LIKE $1", Join(namespace, "%"))
	if err != nil {
		return err
	}
	return nil
}

func (s *SQLDB) Update(ctx context.Context, namespace string, key string, values map[string]any) ([]byte, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {
			logrus.WithError(err).Error("unable to rollback")
		}
	}(tx)
	updater := NewUpdater(values)
	updatedValue, err := updateValue(ctx, namespace, key, updater, tx)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updatedValue, nil
}

func (s *SQLDB) UpdateValueAndOperation(ctx context.Context, namespace, key string, updater Updater, opNamespace, opKey string, opUpdater ResponseSettingUpdater) (first, op []byte, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {
			logrus.WithError(err).Error("unable to rollback")
		}
	}(tx)

	updatedValue, err := updateValue(ctx, namespace, key, updater, tx)
	if err != nil {
		return nil, nil, err
	}

	opUpdater.SetUpdatedResponse(updatedValue)

	updatedOpValue, err := updateValue(ctx, opNamespace, opKey, opUpdater, tx)

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return updatedValue, updatedOpValue, err
}

func updateValue(ctx context.Context, namespace string, key string, updater Updater, tx *sql.Tx) ([]byte, error) {
	currentValue, err := read(ctx, tx, namespace, key)
	if err != nil {
		return nil, err
	}
	if err := updater.Validate(currentValue); err != nil {
		return nil, errors.Wrap(err, "validating update")
	}
	updatedValue, err := updater.Update(currentValue)
	if err != nil {
		return nil, err
	}
	encodedUpdatedValue := base64.RawStdEncoding.EncodeToString(updatedValue)
	_, err = tx.ExecContext(ctx, "UPDATE key_values SET value = $1 WHERE key = $2", encodedUpdatedValue, Join(namespace, key))
	if err != nil {
		return nil, err
	}
	return updatedValue, nil
}

type sqlTx struct {
	tx *sql.Tx
}

func (s *sqlTx) Write(ctx context.Context, namespace, key string, value []byte) error {
	return write(ctx, s.tx, namespace, key, value)
}

func (s *SQLDB) Execute(ctx context.Context, businessLogicFunc BusinessLogicFunc, _ []WatchKey) (any, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil {
			logrus.Errorf("problem rolling back %s", err)
		}
	}(tx)

	bTx := sqlTx{tx: tx}

	result, err := businessLogicFunc(ctx, &bTx)
	if err != nil {
		return nil, errors.Wrap(err, "executing business logic func")
	}

	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "committing transaction")
	}
	return result, nil
}

var _ Tx = (*sqlTx)(nil)
var _ ServiceStorage = (*SQLDB)(nil)

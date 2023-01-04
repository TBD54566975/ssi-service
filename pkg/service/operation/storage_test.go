package operation

import (
	"os"
	"testing"

	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	manifeststg "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/credential"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage/namespace"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func setupTestDB(t *testing.T) storage.ServiceStorage {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	s, err := storage.NewStorage(storage.Bolt, name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		_ = file.Close()
		_ = os.Remove(name)
	})
	return s
}

func TestStorage_CancelOperation(t *testing.T) {
	s := setupTestDB(t)
	data, err := json.Marshal(manifeststg.StoredApplication{})
	require.NoError(t, err)
	require.NoError(t, s.Write(credential.ApplicationNamespace, "hello", data))

	type fields struct {
		db storage.ServiceStorage
	}
	type args struct {
		id string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *opstorage.StoredOperation
		wantErr bool
		done    bool
	}{
		{
			name: "bad id returns error",
			fields: fields{
				db: s,
			},
			args: args{
				id: "hello",
			},
			wantErr: true,
		},
		{
			name: "operation for application can be cancelled",
			fields: fields{
				db: s,
			},
			args: args{
				id: "credentials/responses/hello",
			},
			want: &opstorage.StoredOperation{
				ID:   "credentials/responses/hello",
				Done: true,
			},
		},
		{
			name: "done operation returns error on cancellation",
			done: true,
			fields: fields{
				db: s,
			},
			args: args{
				id: "credentials/responses/hello",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			opData, err := json.Marshal(opstorage.StoredOperation{
				ID:   "credentials/responses/hello",
				Done: tt.done,
			})
			require.NoError(t, err)
			require.NoError(t, s.Write(namespace.FromParent("credentials/responses"), "credentials/responses/hello", opData))

			b := Storage{
				db: tt.fields.db,
			}
			got, err := b.CancelOperation(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("CancelOperation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpopts.IgnoreFields(opstorage.StoredOperation{}, "Response")); diff != "" {
				t.Errorf("CancelOperation() -got, +want:\n%s", diff)
			}
		})
	}
}

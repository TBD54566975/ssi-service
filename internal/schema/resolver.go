package schema

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/schema"
)

// Resolution is an interface that defines a generic method of resolving a schema
type Resolution interface {
	Resolve(ctx context.Context, id string) (*schema.JSONSchema, *schema.VCJSONSchema, schema.VCJSONSchemaType, error)
}

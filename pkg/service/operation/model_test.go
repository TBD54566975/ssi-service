package operation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubmissionID(t *testing.T) {
	tests := []struct {
		name string
		opID string
		want string
	}{
		{
			name: "normal op id returns last word",
			opID: "presentations/submissions/a30e3b91-fb77-4d22-95fa-871689c322e2",
			want: "a30e3b91-fb77-4d22-95fa-871689c322e2",
		},
		{
			name: "op id with no id returns empty",
			opID: "presentations/submissions/",
			want: "",
		},
		{
			name: "crazy id returns empty",
			opID: "some crazy string",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SubmissionID(tt.opID))
		})
	}
}

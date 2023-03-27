package did

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
)

func TestGetVerificationInformation(t *testing.T) {
	publicKey := map[string]struct {
		base58    string
		publicKey crypto.PublicKey
	}{
		"kid2": {
			base58:    "4HyjANoMdhpp952YPb4wALydQRQ7BmsXHmBdwq4YSyiR",
			publicKey: ed25519.PublicKey{0x30, 0xec, 0x7e, 0xbc, 0x71, 0xf, 0x76, 0xd1, 0xad, 0x90, 0x39, 0xb9, 0x94, 0xcd, 0x80, 0x9c, 0x42, 0x72, 0x94, 0x92, 0xf1, 0x46, 0xaf, 0xcc, 0x89, 0x9e, 0x8b, 0xe5, 0xcb, 0xd2, 0x47, 0xfa},
		},
		"an awesome kid": {
			base58:    "z6MkgeW28gvxZGKzGchuPHpNeju7VKcx4ZAJue8N5RNa3qR5",
			publicKey: ed25519.PublicKey{0x2, 0x3c, 0x2e, 0xdc, 0xec, 0x41, 0xbe, 0xa6, 0x33, 0x91, 0xe8, 0x60, 0xbe, 0x13, 0xda, 0x44, 0xe6, 0x69, 0x61, 0xa3, 0x9a, 0xf3, 0x68, 0x6a, 0xb6, 0xd3, 0xd5, 0xf4, 0xb1, 0x15, 0x4, 0x44, 0x89, 0x4c, 0xf4, 0xb4},
		},
	}

	kid2Method := did.VerificationMethod{
		ID:              "kid2",
		Type:            "Ed25519",
		PublicKeyBase58: publicKey["kid2"].base58,
	}
	awesomeKidMethod := did.VerificationMethod{
		ID:              "an awesome kid",
		Type:            "Ed25519",
		PublicKeyBase58: publicKey["an awesome kid"].base58,
	}
	type args struct {
		did      did.DIDDocument
		maybeKID string
	}
	tests := []struct {
		name       string
		args       args
		wantKid    string
		wantPubKey crypto.PublicKey
		wantErr    assert.ErrorAssertionFunc
	}{
		{
			name: "multiple method return the correct public key",
			args: args{
				did: did.DIDDocument{
					ID: "my doc id",
					VerificationMethod: []did.VerificationMethod{
						kid2Method,
						awesomeKidMethod,
					},
				},
				maybeKID: "kid2",
			},
			wantKid:    "kid2",
			wantPubKey: publicKey["kid2"].publicKey,
			wantErr:    assert.NoError,
		},
		{
			name: "single verification method without maybekid",
			args: args{
				did: did.DIDDocument{
					ID: "my doc id",
					VerificationMethod: []did.VerificationMethod{
						awesomeKidMethod,
					},
				},
				maybeKID: "",
			},
			wantKid:    "my doc id",
			wantPubKey: publicKey["an awesome kid"].publicKey,
			wantErr:    assert.NoError,
		},
		{
			name: "single verification method with maybekid",
			args: args{
				did: did.DIDDocument{
					ID: "my doc id",
					VerificationMethod: []did.VerificationMethod{
						awesomeKidMethod,
					},
				},
				maybeKID: "an awesome kid",
			},
			wantKid:    "my doc id",
			wantPubKey: publicKey["an awesome kid"].publicKey,
			wantErr:    assert.NoError,
		},
		{
			name: "things not great",
			args: args{
				did: did.DIDDocument{
					ID: "my doc id",
					VerificationMethod: []did.VerificationMethod{
						kid2Method,
						awesomeKidMethod,
					},
				},
				maybeKID: "an awesome kid",
			},
			wantKid:    "an awesome kid",
			wantPubKey: publicKey["an awesome kid"].publicKey,
			wantErr:    assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKid, gotPubKey, err := GetVerificationInformation(tt.args.did, tt.args.maybeKID)
			if !tt.wantErr(t, err, fmt.Sprintf("GetVerificationInformation(%v, %v)", tt.args.did, tt.args.maybeKID)) {
				return
			}
			assert.Equalf(t, tt.wantKid, gotKid, "GetVerificationInformation(%v, %v)", tt.args.did, tt.args.maybeKID)
			assert.Equalf(t, tt.wantPubKey, gotPubKey, "GetVerificationInformation(%v, %v)", tt.args.did, tt.args.maybeKID)
		})
	}
}

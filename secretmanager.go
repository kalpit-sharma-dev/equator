package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LoadKey fetches the AES-256 key from GCP Secret Manager.
//
// The secret payload must be the 32-byte key stored as Base64. After the
// payload is fetched, it is Base64-decoded and strictly validated to be
// exactly 32 bytes.
//
// version defaults to "latest" when empty so day-to-day Ops use is unchanged.
// During a key rotation, pass an explicit numeric version to decrypt records
// that were encrypted under an older key version.
func LoadKey(ctx context.Context, project, secretName, version string) ([]byte, error) {
	if project == "" {
		return nil, fmt.Errorf("project is required")
	}
	if secretName == "" {
		return nil, fmt.Errorf("secret name is required")
	}
	if version == "" {
		version = "latest"
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}
	defer client.Close()

	name := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", project, secretName, version)
	req := &secretmanagerpb.AccessSecretVersionRequest{Name: name}

	resp, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.PermissionDenied, codes.Unauthenticated:
				return nil, fmt.Errorf("secret manager access denied: check service account IAM permissions")
			case codes.NotFound:
				return nil, fmt.Errorf("secret not found: %s", name)
			}
		}
		return nil, fmt.Errorf("failed to access secret: %w", err)
	}

	payload := resp.GetPayload().GetData()
	if len(payload) == 0 {
		return nil, fmt.Errorf("secret payload is empty")
	}

	// Secret Manager may return the payload with surrounding whitespace if it
	// was pasted in via the console; trim it before Base64 decoding.
	trimmed := strings.TrimSpace(string(payload))

	key, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode secret payload: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: got %d bytes, want 32", len(key))
	}
	return key, nil
}

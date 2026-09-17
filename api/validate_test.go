package api_test

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func validate(t *testing.T, path string) {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		t.Fatalf("loading %s: %v", path, err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("validating %s: %v", path, err)
	}
}

func TestPublicAPI_IsValidOpenAPI(t *testing.T) {
	validate(t, "public.yaml")
}

func TestAdminAPI_IsValidOpenAPI(t *testing.T) {
	validate(t, "admin.yaml")
}

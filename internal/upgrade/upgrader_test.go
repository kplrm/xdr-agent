package upgrade

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestPackageURL(t *testing.T) {
	for _, debian := range []bool{true, false} {
		url, err := packageURL("1.2.3", debian)
		if err != nil || !strings.Contains(url, "/v1.2.3/") {
			t.Fatalf("%s %v", url, err)
		}
	}
}
func TestDownloadArtifact(t *testing.T) {
	for _, status := range []int{200, 404} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); w.Write([]byte("fixture")) }))
		path, err := download(context.Background(), server.URL, t.TempDir(), ".deb")
		server.Close()
		if status == 200 {
			if err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(path)
			if string(data) != "fixture" {
				t.Fatal("wrong content")
			}
		} else if err == nil {
			t.Fatal("accepted missing release")
		}
	}
}

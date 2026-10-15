package upgrade

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPackageURL(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		url, err := packageURL("1.2.3", arch)
		if err != nil || url != githubReleaseBase+"/v1.2.3/xdr-agent_1.2.3_"+arch+".deb" {
			t.Fatalf("%s %v", url, err)
		}
	}
	for _, version := range []string{"latest", "v1.2.3", "1.2.3/../../other", "1.2.3;id"} {
		if _, err := packageURL(version, "amd64"); err == nil {
			t.Fatalf("accepted unsafe version: %s", version)
		}
	}
	if _, err := packageURL("1.2.3", "386"); err == nil {
		t.Fatal("accepted unsupported architecture")
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

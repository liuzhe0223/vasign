package vasign

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

func signingString(req *http.Request, timestamp, nonce string, body []byte) string {
	path := ""
	rawQuery := ""
	if req.URL != nil {
		path = req.URL.EscapedPath()
		rawQuery = req.URL.RawQuery
	}

	bodyHash := sha256.Sum256(body)
	return req.Method + "\n" +
		canonicalHost(req) + "\n" +
		path + "\n" +
		rawQuery + "\n" +
		timestamp + "\n" +
		nonce + "\n" +
		hex.EncodeToString(bodyHash[:])
}

func canonicalHost(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}

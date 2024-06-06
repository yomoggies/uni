package franchise

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yomoggies/uni/franchise/internal"
	"net/http"
	"net/url"
	"path"
	"time"
)

type Token struct {
	AuthorizationHeader string                   `json:"authorizationHeader,omitempty"`
	ValidUntil          time.Time                `json:"validUntil,omitempty"`
	Treatments          []string                 `json:"treatments,omitempty"`
	Configurations      map[string]Configuration `json:"configurations,omitempty"`
	TreatmentContext    string                   `json:"treatmentContext,omitempty"`
}

func (t *Token) SetAuthHeader(req *http.Request) {
	req.Header.Set("Authorization", t.AuthorizationHeader)
}

type Configuration struct {
	ID         string            `json:"id,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

func (c *TokenConfig) Token() (*Token, error) {
	u, err := url.Parse(c.Environment.ServiceURI)
	if err != nil {
		return nil, fmt.Errorf("parse service URI: %w", err)
	}
	u.Path = path.Join("/api/v1.0/session/start")

	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(c); err != nil {
		return nil, fmt.Errorf("encode request body: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), buf)
	if err != nil {
		return nil, fmt.Errorf("make request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: %s", req.Method, req.URL, resp.Status)
	}
	var result internal.Result[Token]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response body: %w", err)
	}
	if result.Data.AuthorizationHeader == "" {
		return nil, errors.New("no authorization header")
	}
	return &result.Data, nil
}

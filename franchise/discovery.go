package franchise

import (
	"encoding/json"
	"fmt"
	"github.com/yomoggies/uni/franchise/internal"
	"net/http"
	"net/url"
	"path"
)

func Discover(build string) (*Discovery, error) {
	u := &url.URL{
		Scheme: "https",
		Host:   "client.discovery.minecraft-services.net",
		Path:   path.Join("/api/v1.0/discovery/MinecraftPE/builds", build),
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("make request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: %s", req.Method, req.URL, err)
	}
	var result internal.Result[Discovery]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response body: %w", err)
	}
	return &result.Data, nil
}

type Discovery struct {
	ServiceEnvironments   map[string]map[EnvironmentType]json.RawMessage `json:"serviceEnvironments,omitempty"`
	SupportedEnvironments map[string][]EnvironmentType                   `json:"supportedEnvironments,omitempty"`
}

func (d *Discovery) Environment(name string, typ EnvironmentType) (json.RawMessage, bool) {
	e, ok := d.ServiceEnvironments[name]
	if !ok {
		return nil, false
	}
	env, ok := e[typ]
	if !ok {
		return nil, false
	}
	return env, true
}

type EnvironmentType string

const (
	EnvironmentTypeProduction  EnvironmentType = "prod"
	EnvironmentTypeDevelopment EnvironmentType = "dev"
	EnvironmentTypeStage       EnvironmentType = "stage"
)

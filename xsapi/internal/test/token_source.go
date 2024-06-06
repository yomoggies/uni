package test

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"os"
	"path/filepath"
)

func ReadTokenSource(path string, src oauth2.TokenSource) (tok *oauth2.Token, err error) {
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat: %w", err)
		}
		tok, err = src.Token()
		if err != nil {
			return nil, fmt.Errorf("request token: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
			return nil, fmt.Errorf("make parent directories: %w", err)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
		if err != nil {
			return nil, err // the operation above is already wrapped with fs.PathError
		}
		defer f.Close()
		if err := json.NewEncoder(f).Encode(tok); err != nil {
			return nil, fmt.Errorf("encode: %w", err)
		}
		return tok, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err // the operation above is already wrapped with fs.PathError
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&tok); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return
}

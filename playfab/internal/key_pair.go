package internal

import "fmt"

func KeyPair[K comparable, V any](slice []any) (map[K]V, error) {
	if len(slice)%2 != 0 {
		return nil, fmt.Errorf("playfab/internal: KeyPair: invalid length: %d, expected an even", len(slice))
	}

	m := make(map[K]V, len(slice)*2)
	for i := 0; i < len(slice); i += 2 {
		key, ok := slice[i].(K)
		if !ok {
			return nil, fmt.Errorf("playfab/internal: KeyPair: #%d: invalid key: %T, expected %T", i, slice[i], *new(K))
		}
		val, ok := slice[i+1].(V)
		if !ok {
			return nil, fmt.Errorf("playfab/internal: KeyPair: #%d: invalid value: %T, expected %T", i+1, slice[i+1], *new(V))
		}
		m[key] = val
	}
	return m, nil
}

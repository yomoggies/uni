package entity

import (
	"fmt"
	"github.com/yomoggies/uni/playfab/internal"
	"github.com/yomoggies/uni/playfab/title"
)

func (tok *Token) Exchange(t title.Title, id string, customTags ...any) (_ *Token, err error) {
	r := exchange{
		Entity: Key{
			Type: TypeMasterPlayerAccount,
			ID:   id,
		},
	}
	if len(customTags) > 0 {
		r.CustomTags, err = internal.KeyPair[string, any](customTags)
		if err != nil {
			return nil, fmt.Errorf("parse custom tags: %w", err)
		}
	}

	return internal.Do[*Token](t, "/Authentication/GetEntityToken", r, tok.SetAuthHeader)
}

type exchange struct {
	CustomTags map[string]any `json:"CustomTags,omitempty"`
	Entity     Key            `json:"Entity,omitempty"`
}

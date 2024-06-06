package title

import (
	"errors"
	"fmt"
	"strconv"
)

type Title int64

func Parse(s string) (Title, error) {
	id, err := strconv.ParseInt(s, 16, 64)
	if err != nil {
		return -1, fmt.Errorf("parse integer: %w", err)
	}
	return Title(id), nil
}

func MustParse(s string) Title {
	t, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return t
}

func (t Title) Route(path string) string {
	return "https://" + t.String() + ".playfabapi.com" + path
}

func (t Title) String() string { return strconv.FormatInt(int64(t), 16) }

//goland:noinspection GoMixedReceiverTypes
func (t *Title) Set(s string) (err error) {
	if t == nil {
		return errNilUnmarshal
	}
	*t, err = Parse(s)
	return err
}

func (t Title) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

//goland:noinspection GoMixedReceiverTypes
func (t *Title) UnmarshalText(b []byte) (err error) {
	if t == nil {
		return errNilUnmarshal
	}
	*t, err = Parse(string(b))
	return err
}

var errNilUnmarshal = errors.New("title: cannot unmarshal a nil *Title")

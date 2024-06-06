package internal

import "log/slog"

const errAttrKey = "error"

func ErrAttr(err error) slog.Attr {
	return slog.Any(errAttrKey, err)
}

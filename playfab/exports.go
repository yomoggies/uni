package playfab

import "github.com/yomoggies/uni/playfab/internal"

type Body[T any] internal.Body[T]

type Error = internal.Error

const (
	ErrorCodeSuccess = iota
	ErrorCodeUnknown
	ErrorCodeConnectionError
	ErrorCodeJSONParseError
)

const (
	ErrorCodeInvalidRequest             = 1071
	ErrorCodeItemNotFound               = 1047
	ErrorCodeDatabaseThroughputExceeded = 1113
	NotImplemented                      = 1515
)

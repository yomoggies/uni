package room

import (
	"context"
	"github.com/yomoggies/uni/xsapi"
	"github.com/yomoggies/uni/xsapi/mpsd"
	"log/slog"
)

type PublishConfig struct {
	SessionConfig  mpsd.PublishConfig
	StatusProvider StatusProvider
	Logger         *slog.Logger
}

func (conf PublishConfig) PublishContext(ctx context.Context, src xsapi.TokenSource) (*Room, error) {

}

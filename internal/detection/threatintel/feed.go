package threatintel

import "errors"

var ErrPluginManagedFeed = errors.New("threat intelligence feeds are managed by xdr-defense plugin; agent accepts local artifacts only")

type Feed struct{}

func NewFeed() *Feed { return &Feed{} }

func (f *Feed) PullRemote() error {
	return ErrPluginManagedFeed
}

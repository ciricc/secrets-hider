package secretshider

import "regexp"

const DefaultMask string = "********"

type Options struct {
	// Which secrets tokens needs to hide
	secretsTokensList []*regexp.Regexp
	// Which mask will be used to replace secret value
	mask string
}

type Option func(opts *Options) error

func WithMask(mask string) Option {
	return func(opts *Options) error {
		opts.mask = mask

		return nil
	}
}

// Which secrets tokens needs to be replace
func WithSecretsTokens(secrets ...*regexp.Regexp) Option {
	return func(opts *Options) error {
		opts.secretsTokensList = secrets

		return nil
	}
}

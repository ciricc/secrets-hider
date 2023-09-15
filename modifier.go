package secretshider

import (
	"fmt"
	"regexp"

	zerologgrpcprovider "github.com/ciricc/zerolog-grpc-provider"
)

// NewModifier returns modifier for zerolog grpc provider package to hide
// sensitive information from the logs
//
// You can set secrets tokens list of the regexp.Regexp to say which keys
// of the request fields needs to be hidden from the logs (/password/i and etc)
//
// If you want to modify mask of the hiddent value, you can set
// WithMask option and provide string value like "SECRET_KEY" or "****"
func NewModifier(opts ...Option) (zerologgrpcprovider.RequestValueModifier, error) {
	options := &Options{
		secretsTokensList: []*regexp.Regexp{
			regexp.MustCompile(`(?i)password|secret|token|key|pass|pin|code|seed`),
		},
		mask: DefaultMask,
	}

	for _, opt := range opts {
		err := opt(options)
		if err != nil {
			return nil, fmt.Errorf("failed to set option: %w", err)
		}
	}

	return func(key string, value any) (newValue any, err error) {
		for _, secretToken := range options.secretsTokensList {
			_, isMapValue := value.(map[string]interface{})
			if secretToken.MatchString(key) && !isMapValue {
				return options.mask, nil
			}
		}

		return value, nil
	}, nil
}

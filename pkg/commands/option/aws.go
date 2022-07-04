package option

import (
	"github.com/urfave/cli/v2"
)

// AWSOption holds the options for AWS scanning
type AWSOption struct {
	Region   string
	Endpoint string
	Services []string
}

// NewAWSOption is the factory method to return AWS options
func NewAWSOption(c *cli.Context) AWSOption {
	return AWSOption{
		Region:   c.String("region"),
		Endpoint: c.String("endpoint"),
		Services: c.StringSlice("service"),
	}
}

package option

import (
	"os"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

// ArtifactOption holds the options for an artifact scanning
type ArtifactOption struct {
	Input      string
	Timeout    time.Duration
	ClearCache bool

	SkipDirs    []string
	SkipFiles   []string
	OfflineScan bool

	// this field is populated in Init()
	Target string
}

// NewArtifactOption is the factory method to return artifact option
func NewArtifactOption(c *cli.Context) ArtifactOption {
	return ArtifactOption{
		Input:       c.String("input"),
		Timeout:     c.Duration("timeout"),
		ClearCache:  c.Bool("clear-cache"),
		SkipFiles:   c.StringSlice("skip-files"),
		SkipDirs:    c.StringSlice("skip-dirs"),
		OfflineScan: c.Bool("offline-scan"),
	}
}

// Init initialize the CLI context for artifact scanning
func (c *ArtifactOption) Init(ctx *cli.Context, logger *zap.SugaredLogger) (err error) {

	switch ctx.Command.Name {
	case "aws":
		if ctx.Args().Len() > 0 {
			logger.Error(`targets should not be specified for the "aws" command`)
			return xerrors.New("arguments error")
		}
		return nil
	case "kubernetes":
		if c.Input == "" && ctx.Args().Len() == 0 {
			logger.Debug(`trivy kubernetes requires at least 1 argument or --input option`)
			_ = cli.ShowSubcommandHelp(ctx) // nolint: errcheck
			os.Exit(0)
		}
	default:
		if ctx.Args().Len() != 1 {
			logger.Error(`exactly one target must be specified`)
			return xerrors.New("arguments error")
		}
	}

	if c.Input == "" {
		c.Target = ctx.Args().First()
	}
	return nil
}

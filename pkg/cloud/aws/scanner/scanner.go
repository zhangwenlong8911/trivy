package scanner

import (
	"context"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"

	"github.com/aquasecurity/defsec/pkg/scan"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type AWSScanner struct {
}

func NewScanner() *AWSScanner {
	return &AWSScanner{}
}

func (s *AWSScanner) Scan(ctx context.Context, option cmd.Option) (scan.Results, error) {

	// TODO: check if misconfigurations should be scanned for

	var scannerOpts []options.ScannerOption
	if !option.NoProgress {
		tracker := newMultibar()
		defer tracker.serviceBar.Finish()
		scannerOpts = append(scannerOpts, scanner.ScannerWithProgressTracker(tracker))
	}

	if len(option.Services) > 0 {
		scannerOpts = append(scannerOpts, scanner.ScannerWithAWSServices(option.Services...))
	}

	defsecResults, err := scanner.New(scannerOpts...).Scan(ctx)
	if err != nil {
		return nil, err
	}

	return defsecResults, nil
}

package report

import (
	"fmt"
)

func writeResultsForARN(report *Report, option Option) error {
	//
	//w, _, err := term.GetSize(0)
	//if err != nil {
	//	w = 80
	//}

	// render scan title
	_, _ = fmt.Fprintf(option.Output, "\n\x1b[1m  '%s' (AWS Account %s)\x1b[0m\n", option.Service, report.AccountID)

	for _, result := range report.Results {
		for _, misconfiguration := range result.Misconfigurations {
			if misconfiguration.CauseMetadata.Resource != option.ARN {
				continue
			}
			fmt.Println(misconfiguration.ID + ": " + misconfiguration.CauseMetadata.Resource)
		}
	}

	// render cache info
	if option.FromCache {
		_, _ = fmt.Fprintf(option.Output, "\n\x1b[34mThis scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.\x1b[0m\n")
	}

	return nil
}

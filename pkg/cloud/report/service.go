package report

import (
	"fmt"
	"strconv"

	"github.com/aquasecurity/table"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
)

func writeServiceTable(report *Report, option Option) error {

	t := table.New(option.Output)

	t.SetHeaders("Service", "Misconfigurations")
	t.AddHeaders("Service", "Critical", "High", "Medium", "Low", "Unknown")
	t.SetAlignment(table.AlignLeft, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter)
	t.SetAutoMergeHeaders(true)
	t.SetHeaderColSpans(0, 1, 5)

	// map service -> severity -> count
	grouped := make(map[string]map[string]int)
	for _, result := range report.Results {
		for _, misconfiguration := range result.Misconfigurations {
			if _, ok := grouped[misconfiguration.CauseMetadata.Service]; !ok {
				grouped[misconfiguration.CauseMetadata.Service] = make(map[string]int)
			}
			grouped[misconfiguration.CauseMetadata.Service][misconfiguration.Severity]++
		}
	}

	for service, severityCounts := range grouped {
		t.AddRow(
			service,
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["CRITICAL"]), "CRITICAL"),
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["HIGH"]), "HIGH"),
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["MEDIUM"]), "MEDIUM"),
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["LOW"]), "LOW"),
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["UNKNOWN"]), "UNKNOWN"),
		)
	}

	// render scan title
	_, _ = fmt.Fprintf(option.Output, "\n\x1b[1mScan Overview for AWS Account %s\x1b[0m\n", report.AccountID)

	// render table
	t.Render()

	// TODO: render individual results if necessary

	// render cache info
	if option.FromCache {
		_, _ = fmt.Fprintf(option.Output, "\n\x1b[34mThis scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.\x1b[0m\n")
	}

	return nil
}

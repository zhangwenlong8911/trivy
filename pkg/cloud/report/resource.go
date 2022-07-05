package report

import (
	"fmt"
	"strconv"

	"golang.org/x/term"

	"github.com/aquasecurity/table"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
)

func writeResourceTable(report *Report, option Option) error {

	t := table.New(option.Output)

	w, _, err := term.GetSize(0)
	if err != nil {
		w = 80
	}
	maxWidth := w - 60
	if maxWidth < 20 {
		maxWidth = 20
	}

	t.SetColumnMaxWidth(maxWidth)
	t.SetHeaders("Resource", "Misconfigurations")
	t.AddHeaders("Resource", "Critical", "High", "Medium", "Low", "Unknown")
	t.SetAlignment(table.AlignLeft, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter)
	t.SetRowLines(false)
	t.SetAutoMergeHeaders(true)
	t.SetHeaderColSpans(0, 1, 5)

	// map resource -> severity -> count
	grouped := make(map[string]map[string]int)
	for _, result := range report.Results {
		for _, misconfiguration := range result.Misconfigurations {
			if _, ok := grouped[misconfiguration.CauseMetadata.Resource]; !ok {
				grouped[misconfiguration.CauseMetadata.Resource] = make(map[string]int)
			}
			grouped[misconfiguration.CauseMetadata.Resource][misconfiguration.Severity]++
		}
	}

	for resource, severityCounts := range grouped {
		t.AddRow(
			resource,
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["CRITICAL"]), "CRITICAL"),
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["HIGH"]), "HIGH"),
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["MEDIUM"]), "MEDIUM"),
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["LOW"]), "LOW"),
			pkgReport.ColorizeSeverity(strconv.Itoa(severityCounts["UNKNOWN"]), "UNKNOWN"),
		)
	}

	// render scan title
	_, _ = fmt.Fprintf(option.Output, "\n\x1b[1mResource Summary for Service '%s' (AWS Account %s)\x1b[0m\n", option.Service, report.AccountID)

	// render table
	t.Render()

	// TODO: render individual results if necessary

	// render cache info
	if option.FromCache {
		_, _ = fmt.Fprintf(option.Output, "\n\x1b[34mThis scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.\x1b[0m\n")
	}

	return nil
}

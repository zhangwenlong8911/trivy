package asff

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
)

const (
	vulnLimit          = 100 // AWS SecurityHub only accepts reports with 100 or fewer findings.
	fileNamePartFormat = "part%d_%s"
)

// ASFFWriter implements result Writer
type ASFFWriter struct {
	Output io.Writer
}

// Write writes the results in ASFF format
func (aw ASFFWriter) Write(report types.Report) error {
	target := report.Results[0].Target
	parts := len(report.Results[0].Vulnerabilities) / vulnLimit // number of files by vulnerability limit
	file := aw.Output.(*os.File)
	outputs := make(map[io.Writer][]types.DetectedVulnerability)

	if aw.Output == os.Stdout || parts == 0 {
		outputs[aw.Output] = report.Results[0].Vulnerabilities
	} else {
		fileName := filepath.Base(file.Name())
		dir := filepath.Dir(file.Name())
		// remove base file(created earlier) to create multiple files
		os.Remove(filepath.Join(dir, fileName))
		// split report into multiple files
		for i := 0; i < parts; i++ {
			writer, err := os.Create(filepath.Join(dir, fmt.Sprintf(fileNamePartFormat, i, fileName)))
			if err != nil {
				return xerrors.Errorf("failed to create output: %w", err)
			}
			outputs[writer] = report.Results[0].Vulnerabilities[i*vulnLimit : i*vulnLimit+vulnLimit]
		}
		vulns := report.Results[0].Vulnerabilities[parts*vulnLimit:]
		if len(vulns) > 0 {
			writer, err := os.Create(filepath.Join(dir, fmt.Sprintf(fileNamePartFormat, parts, fileName)))
			if err != nil {
				return xerrors.Errorf("failed to create output: %w", err)
			}
			outputs[writer] = vulns
		}
	}
	for writer, vulns := range outputs {
		out, err := createFormattedOutput(target, vulns)
		if err != nil {
			return xerrors.Errorf("failed to format output: %w", err)
		}
		if _, err := fmt.Fprintln(writer, string(out)); err != nil {
			return xerrors.Errorf("failed to write json: %w", err)
		}
	}
	return nil
}

func createFormattedOutput(target string, vulns []types.DetectedVulnerability) ([]byte, error) {
	var asff Asff

	for _, vuln := range vulns {
		description := vuln.Description
		if len(description) > 512 {
			description = fmt.Sprintf("%s ..", description[:512])
		}
		image := target
		if l := len(image); l > 127 {
			image = fmt.Sprintf("...%s", image[l-124:])
		}
		severity := vuln.Severity
		if severity == "UNKNOWN" {
			severity = "INFORMATIONAL"
		}

		finding := Finding{
			SchemaVersion: "2018-10-08",
			Id:            fmt.Sprintf("%s/%s", target, vuln.VulnerabilityID),
			ProductArn:    fmt.Sprintf("arn:aws:securityhub:%s::product/aquasecurity/aquasecurity", os.Getenv("AWS_REGION")),
			GeneratorId:   fmt.Sprintf("Trivy/%s", vuln.VulnerabilityID),
			AwsAccountId:  os.Getenv("AWS_ACCOUNT_ID"),
			Types:         []string{"Software and Configuration Checks/Vulnerabilities/CVE"},
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			Severity:      Severity{Label: severity},
			Title:         fmt.Sprintf("Trivy found a vulnerability to %s in container %s", vuln.VulnerabilityID, target),
			Description:   description,
			Remediation: Remediation{Recommendation: Recommendation{
				Text: "More information on this vulnerability is provided in the hyperlink",
				Url:  vuln.PrimaryURL,
			},
			},
			ProductFields: ProductFields{ProductName: "Trivy"},
			Resources: []Resource{
				{
					Type:      "Container",
					Id:        target,
					Partition: "aws",
					Region:    os.Getenv("AWS_REGION"),
					Details: Details{
						Container: Container{ImageName: image},
						Other: Other{
							CVEID:            vuln.VulnerabilityID,
							CVETitle:         vuln.Title,
							PkgName:          vuln.PkgName,
							InstalledPackage: vuln.InstalledVersion,
							PatchedPackage:   vuln.FixedVersion,
							NvdCvssScoreV3:   fmt.Sprintf("%g", vuln.CVSS["nvd"].V3Score),
							NvdCvssVectorV3:  vuln.CVSS["nvd"].V3Vector,
							NvdCvssScoreV2:   fmt.Sprintf("%g", vuln.CVSS["nvd"].V2Score),
							NvdCvssVectorV2:  vuln.CVSS["nvd"].V2Vector,
						},
					},
				},
			},
			RecordState: "ACTIVE",
		}
		asff.Findings = append(asff.Findings, finding)
	}
	output, err := json.MarshalIndent(asff, "", "    ")
	if err != nil {
		return nil, xerrors.Errorf("failed to marshal json: %w", err)
	}
	return output, nil
}

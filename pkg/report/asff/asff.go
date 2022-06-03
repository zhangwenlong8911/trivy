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

const vulnLimit = 100

// ASFFWriter implements result Writer
type ASFFWriter struct {
	Output io.Writer
}

type result struct {
	fileName        string
	Vulnerabilities *[]types.DetectedVulnerability
}

// Write writes the results in JSON format
func (aw ASFFWriter) Write(report types.Report) error {
	target := report.Results[0].Target
	parts := len(report.Results[0].Vulnerabilities) / vulnLimit // number of files by vulnerability limit
	file := aw.Output.(*os.File)
	outputs := make(map[io.Writer][]byte)
	var results []result

	if aw.Output == os.Stdout || parts == 0 {
		r := result{fileName: file.Name(), Vulnerabilities: &report.Results[0].Vulnerabilities}
		results = append(results, r)

		/*output, err := createFormattedOutput(target, report.Results[0].Vulnerabilities)
		if err != nil {
			return xerrors.Errorf("failed to create output: %w", err)
		}
		outputs[aw.Output] = output*/
	} else {
		for i := 0; i < parts; i++ {
			/*r := result{fileName: }*/
			output, err := createFormattedOutput(target, report.Results[0].Vulnerabilities[i*100:i*100+100])
			if err != nil {
				return xerrors.Errorf("failed to create output: %w", err)
			}
			dir := filepath.Dir(file.Name())
			fileName := fmt.Sprintf("part%d_%s", i, filepath.Base(file.Name()))
			writer, err := os.Create(filepath.Join(dir, fileName))
			outputs[writer] = output
		}
		output, err := createFormattedOutput(report.Results[0].Target, report.Results[0].Vulnerabilities[parts*100:])
		if err != nil {
			return xerrors.Errorf("failed to create output: %w", err)
		}
		dir := filepath.Dir(file.Name())
		fileName := fmt.Sprintf("part%d_%s", parts, filepath.Base(file.Name()))
		writer, err := os.Create(filepath.Join(dir, fileName))
		outputs[writer] = output
	}
	for writer, output := range outputs {
		if _, err := fmt.Fprintln(writer, string(output)); err != nil {
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
			description = description[:512]
		}
		image := target
		if l := len(image); l > 127 {
			image = image[l-124:]
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
	output, err := json.MarshalIndent(asff, "", "  ")
	if err != nil {
		return nil, xerrors.Errorf("failed to marshal json: %w", err)
	}
	return output, nil
}

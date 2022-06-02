package asff

import "time"

type Asff struct {
	Findings []Finding `json:"Findings"`
}

type Finding struct {
	SchemaVersion string        `json:"SchemaVersion"`
	Id            string        `json:"Id"`
	ProductArn    string        `json:"ProductArn"`
	GeneratorId   string        `json:"GeneratorId"`
	AwsAccountId  string        `json:"AwsAccountId"`
	Types         []string      `json:"Types"`
	CreatedAt     time.Time     `json:"CreatedAt"`
	UpdatedAt     time.Time     `json:"UpdatedAt"`
	Severity      Severity      `json:"Severity"`
	Title         string        `json:"Title"`
	Description   string        `json:"Description"`
	Remediation   Remediation   `json:"Recommendation"`
	ProductFields ProductFields `json:"ProductFields"`
	Resources     []Resource    `json:"Resources"`
	RecordState   string        `json:"RecordState"`
}

type Severity struct {
	Label string
}

type Remediation struct {
	Recommendation Recommendation
}

type Recommendation struct {
	Text string `json:"Text"`
	Url  string `json:"Url"`
}

type ProductFields struct {
	ProductName string `json:"Product Name"`
}

type Resource struct {
	Type      string  `json:"Type"`
	Id        string  `json:"Id"`
	Partition string  `json:"Partition"`
	Region    string  `json:"Region"`
	Details   Details `json:"Details"`
}

type Details struct {
	Container Container `json:"Container"`
	Other     Other     `json:"Other"`
}

type Container struct {
	ImageName string `json:"ImageName"`
}

type Other struct {
	CVEID            string `json:"CVE ID"`
	CVETitle         string `json:"CVE Title"`
	PkgName          string `json:"PkgName"`
	InstalledPackage string `json:"Installed Package"`
	PatchedPackage   string `json:"Patched Package"`
	NvdCvssScoreV3   string `json:"NvdCvssScoreV3"`
	NvdCvssVectorV3  string `json:"NvdCvssVectorV3"`
	NvdCvssScoreV2   string `json:"NvdCvssScoreV2"`
	NvdCvssVectorV2  string `json:"NvdCvssVectorV2"`
}

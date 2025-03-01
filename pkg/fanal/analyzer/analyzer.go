package analyzer

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/exp/slices"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	analyzers       = map[Type]analyzer{}
	configAnalyzers = map[Type]configAnalyzer{}

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("no packages detected")
)

type AnalysisInput struct {
	Dir      string
	FilePath string
	Info     os.FileInfo
	Content  dio.ReadSeekerAt

	Options AnalysisOptions
}

type AnalysisOptions struct {
	Offline bool
}

type analyzer interface {
	Type() Type
	Version() int
	Analyze(ctx context.Context, input AnalysisInput) (*AnalysisResult, error)
	Required(filePath string, info os.FileInfo) bool
}

type configAnalyzer interface {
	Type() Type
	Version() int
	Analyze(targetOS types.OS, content []byte) ([]types.Package, error)
	Required(osFound types.OS) bool
}

type Group string

const GroupBuiltin Group = "builtin"

func RegisterAnalyzer(analyzer analyzer) {
	analyzers[analyzer.Type()] = analyzer
}

// DeregisterAnalyzer is mainly for testing
func DeregisterAnalyzer(t Type) {
	delete(analyzers, t)
}

func RegisterConfigAnalyzer(analyzer configAnalyzer) {
	configAnalyzers[analyzer.Type()] = analyzer
}

// DeregisterConfigAnalyzer is mainly for testing
func DeregisterConfigAnalyzer(t Type) {
	delete(configAnalyzers, t)
}

// CustomGroup returns a group name for custom analyzers
// This is mainly intended to be used in Aqua products.
type CustomGroup interface {
	Group() Group
}

type Opener func() (dio.ReadSeekCloserAt, error)

type AnalyzerGroup struct {
	analyzers       []analyzer
	configAnalyzers []configAnalyzer
}

type AnalysisResult struct {
	m                    sync.Mutex
	OS                   *types.OS
	Repository           *types.Repository
	PackageInfos         []types.PackageInfo
	Applications         []types.Application
	Secrets              []types.Secret
	Licenses             []types.LicenseFile
	SystemInstalledFiles []string // A list of files installed by OS package manager

	Files map[types.HandlerType][]types.File

	// For Red Hat
	BuildInfo *types.BuildInfo

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []types.CustomResource
}

func NewAnalysisResult() *AnalysisResult {
	result := new(AnalysisResult)
	result.Files = map[types.HandlerType][]types.File{}
	return result
}

func (r *AnalysisResult) isEmpty() bool {
	return r.OS == nil && r.Repository == nil && len(r.PackageInfos) == 0 && len(r.Applications) == 0 &&
		len(r.Secrets) == 0 && len(r.Licenses) == 0 && len(r.SystemInstalledFiles) == 0 &&
		r.BuildInfo == nil && len(r.Files) == 0 && len(r.CustomResources) == 0
}

func (r *AnalysisResult) Sort() {
	// OS packages
	sort.Slice(r.PackageInfos, func(i, j int) bool {
		return r.PackageInfos[i].FilePath < r.PackageInfos[j].FilePath
	})

	for _, pi := range r.PackageInfos {
		sort.Slice(pi.Packages, func(i, j int) bool {
			return pi.Packages[i].Name < pi.Packages[j].Name
		})
	}

	// Language-specific packages
	sort.Slice(r.Applications, func(i, j int) bool {
		return r.Applications[i].FilePath < r.Applications[j].FilePath
	})

	for _, app := range r.Applications {
		sort.Slice(app.Libraries, func(i, j int) bool {
			if app.Libraries[i].Name != app.Libraries[j].Name {
				return app.Libraries[i].Name < app.Libraries[j].Name
			}
			return app.Libraries[i].Version < app.Libraries[j].Version
		})
	}

	// Custom resources
	sort.Slice(r.CustomResources, func(i, j int) bool {
		return r.CustomResources[i].FilePath < r.CustomResources[j].FilePath
	})

	for _, files := range r.Files {
		sort.Slice(files, func(i, j int) bool {
			return files[i].Path < files[j].Path
		})
	}

	// Secrets
	sort.Slice(r.Secrets, func(i, j int) bool {
		return r.Secrets[i].FilePath < r.Secrets[j].FilePath
	})
	for _, sec := range r.Secrets {
		sort.Slice(sec.Findings, func(i, j int) bool {
			if sec.Findings[i].RuleID != sec.Findings[j].RuleID {
				return sec.Findings[i].RuleID < sec.Findings[j].RuleID
			}
			return sec.Findings[i].StartLine < sec.Findings[j].StartLine
		})
	}

	// License files
	sort.Slice(r.Licenses, func(i, j int) bool {
		if r.Licenses[i].Type != r.Licenses[j].Type {
			return r.Licenses[i].Type < r.Licenses[j].Type
		}
		return r.Licenses[i].FilePath < r.Licenses[j].FilePath
	})
}

func (r *AnalysisResult) Merge(new *AnalysisResult) {
	if new == nil || new.isEmpty() {
		return
	}

	// this struct is accessed by multiple goroutines
	r.m.Lock()
	defer r.m.Unlock()

	if new.OS != nil {
		// OLE also has /etc/redhat-release and it detects OLE as RHEL by mistake.
		// In that case, OS must be overwritten with the content of /etc/oracle-release.
		// There is the same problem between Debian and Ubuntu.
		if r.OS == nil || r.OS.Family == aos.RedHat || r.OS.Family == aos.Debian {
			r.OS = new.OS
		}
	}

	if new.Repository != nil {
		r.Repository = new.Repository
	}

	if len(new.PackageInfos) > 0 {
		r.PackageInfos = append(r.PackageInfos, new.PackageInfos...)
	}

	if len(new.Applications) > 0 {
		r.Applications = append(r.Applications, new.Applications...)
	}

	for t, files := range new.Files {
		if v, ok := r.Files[t]; ok {
			r.Files[t] = append(v, files...)
		} else {
			r.Files[t] = files
		}
	}

	r.Secrets = append(r.Secrets, new.Secrets...)
	r.Licenses = append(r.Licenses, new.Licenses...)
	r.SystemInstalledFiles = append(r.SystemInstalledFiles, new.SystemInstalledFiles...)

	if new.BuildInfo != nil {
		if r.BuildInfo == nil {
			r.BuildInfo = new.BuildInfo
		} else {
			// We don't need to merge build info here
			// because there is theoretically only one file about build info in each layer.
			if new.BuildInfo.Nvr != "" || new.BuildInfo.Arch != "" {
				r.BuildInfo.Nvr = new.BuildInfo.Nvr
				r.BuildInfo.Arch = new.BuildInfo.Arch
			}
			if len(new.BuildInfo.ContentSets) > 0 {
				r.BuildInfo.ContentSets = new.BuildInfo.ContentSets
			}
		}
	}

	r.CustomResources = append(r.CustomResources, new.CustomResources...)
}

func belongToGroup(groupName Group, analyzerType Type, disabledAnalyzers []Type, analyzer any) bool {
	if slices.Contains(disabledAnalyzers, analyzerType) {
		return false
	}

	analyzerGroupName := GroupBuiltin
	if cg, ok := analyzer.(CustomGroup); ok {
		analyzerGroupName = cg.Group()
	}
	if analyzerGroupName != groupName {
		return false
	}

	return true
}

func NewAnalyzerGroup(groupName Group, disabledAnalyzers []Type) AnalyzerGroup {
	if groupName == "" {
		groupName = GroupBuiltin
	}

	var group AnalyzerGroup
	for analyzerType, a := range analyzers {
		if !belongToGroup(groupName, analyzerType, disabledAnalyzers, a) {
			continue
		}
		group.analyzers = append(group.analyzers, a)
	}

	for analyzerType, a := range configAnalyzers {
		if slices.Contains(disabledAnalyzers, analyzerType) {
			continue
		}
		group.configAnalyzers = append(group.configAnalyzers, a)
	}

	return group
}

// AnalyzerVersions returns analyzer version identifier used for cache keys.
func (ag AnalyzerGroup) AnalyzerVersions() map[string]int {
	versions := map[string]int{}
	for _, a := range ag.analyzers {
		versions[string(a.Type())] = a.Version()
	}
	return versions
}

// ImageConfigAnalyzerVersions returns analyzer version identifier used for cache keys.
func (ag AnalyzerGroup) ImageConfigAnalyzerVersions() map[string]int {
	versions := map[string]int{}
	for _, ca := range ag.configAnalyzers {
		versions[string(ca.Type())] = ca.Version()
	}
	return versions
}

func (ag AnalyzerGroup) AnalyzeFile(ctx context.Context, wg *sync.WaitGroup, limit *semaphore.Weighted, result *AnalysisResult,
	dir, filePath string, info os.FileInfo, opener Opener, disabled []Type, opts AnalysisOptions) error {
	if info.IsDir() {
		return nil
	}

	for _, a := range ag.analyzers {
		// Skip disabled analyzers
		if slices.Contains(disabled, a.Type()) {
			continue
		}

		// filepath extracted from tar file doesn't have the prefix "/"
		if !a.Required(strings.TrimLeft(filePath, "/"), info) {
			continue
		}
		rc, err := opener()
		if errors.Is(err, fs.ErrPermission) {
			log.Logger.Debugf("Permission error: %s", filePath)
			break
		} else if err != nil {
			return xerrors.Errorf("unable to open %s: %w", filePath, err)
		}

		if err = limit.Acquire(ctx, 1); err != nil {
			return xerrors.Errorf("semaphore acquire: %w", err)
		}
		wg.Add(1)

		go func(a analyzer, rc dio.ReadSeekCloserAt) {
			defer limit.Release(1)
			defer wg.Done()
			defer rc.Close()

			ret, err := a.Analyze(ctx, AnalysisInput{
				Dir:      dir,
				FilePath: filePath,
				Info:     info,
				Content:  rc,
				Options:  opts,
			})
			if err != nil && !xerrors.Is(err, aos.AnalyzeOSError) {
				log.Logger.Debugf("Analysis error: %s", err)
				return
			}
			if ret != nil {
				result.Merge(ret)
			}
		}(a, rc)
	}

	return nil
}

func (ag AnalyzerGroup) AnalyzeImageConfig(targetOS types.OS, configBlob []byte) []types.Package {
	for _, d := range ag.configAnalyzers {
		if !d.Required(targetOS) {
			continue
		}

		pkgs, err := d.Analyze(targetOS, configBlob)
		if err != nil {
			continue
		}
		return pkgs
	}
	return nil
}

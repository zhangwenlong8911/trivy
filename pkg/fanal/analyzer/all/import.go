package all

import (
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/buildinfo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/nuget"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/mod"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/jar"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/pom"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/npm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pnpm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/yarn"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/php/composer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/packaging"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pipenv"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/poetry"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/bundler"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/gemspec"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/cargo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/mariner"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/release"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/rpm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/repo/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
)

package options

import (
	"io"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
)

type ConfigurableScanner interface {
	SetTraceWriter(io.Writer)
	SetPerResultTracingEnabled(bool)
	SetPolicyDirs(...string)
	SetDataDirs(...string)
	SetPolicyNamespaces(...string)
	SetPolicyReaders([]io.Reader)
	SetPolicyFilesystem(fs.FS)
	SetDataFilesystem(fs.FS)
	SetUseEmbeddedPolicies(bool)
	SetFrameworks(frameworks []framework.Framework)
	SetSpec(spec string)
	SetRegoOnly(regoOnly bool)
	SetRegoErrorLimit(limit int)
	SetUseEmbeddedLibraries(bool)
	SetIncludeDeprecatedChecks(bool)
	SetCustomSchemas(map[string][]byte)
}

type ScannerOption func(s ConfigurableScanner)

func ScannerWithFrameworks(frameworks ...framework.Framework) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetFrameworks(frameworks)
	}
}

func ScannerWithSpec(spec string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetSpec(spec)
	}
}

func ScannerWithPolicyReader(readers ...io.Reader) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyReaders(readers)
	}
}

func ScannerWithEmbeddedPolicies(embedded bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetUseEmbeddedPolicies(embedded)
	}
}

func ScannerWithEmbeddedLibraries(enabled bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetUseEmbeddedLibraries(enabled)
	}
}

func ScannerWithIncludeDeprecatedChecks(enabled bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetIncludeDeprecatedChecks(enabled)
	}
}

// ScannerWithTrace specifies an io.Writer for trace logs (mainly rego tracing) - if not set, they are discarded
func ScannerWithTrace(w io.Writer) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetTraceWriter(w)
	}
}

func ScannerWithPerResultTracing(enabled bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPerResultTracingEnabled(enabled)
	}
}

func ScannerWithPolicyDirs(paths ...string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyDirs(paths...)
	}
}

func ScannerWithDataDirs(paths ...string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetDataDirs(paths...)
	}
}

// ScannerWithPolicyNamespaces - namespaces which indicate rego policies containing enforced rules
func ScannerWithPolicyNamespaces(namespaces ...string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyNamespaces(namespaces...)
	}
}

func ScannerWithPolicyFilesystem(f fs.FS) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyFilesystem(f)
	}
}

func ScannerWithDataFilesystem(f fs.FS) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetDataFilesystem(f)
	}
}

func ScannerWithRegoOnly(regoOnly bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetRegoOnly(regoOnly)
	}
}

func ScannerWithRegoErrorLimits(limit int) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetRegoErrorLimit(limit)
	}
}

func ScannerWithCustomSchemas(schemas map[string][]byte) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetCustomSchemas(schemas)
	}
}

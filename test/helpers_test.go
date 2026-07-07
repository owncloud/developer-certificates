package conformance

import (
	"path/filepath"
	"runtime"
)

// repoRoot returns the repository root directory, resolved relative to this
// test file (which lives in <root>/test). This keeps the harness independent of
// the working directory it is invoked from.
func repoRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(thisFile))
}

// repoPath joins path segments onto the repository root.
func repoPath(parts ...string) string {
	return filepath.Join(append([]string{repoRoot()}, parts...)...)
}

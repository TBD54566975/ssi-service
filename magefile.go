//go:build mage

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	Go = "go"
)

// Build builds the library.
func Build() error {
	fmt.Println("Building library...")
	return sh.Run(Go, "build", "-tags", "jwx_es256k", "./...")
}

// Artifact builds the binary.
func Artifact() error {
	fmt.Println("Building binary...")
	return sh.Run(Go, "build", "-tags", "jwx_es256k", "-o", "./bin/ssi-service", "./cmd")
}

// Vuln downloads and runs govulncheck https://go.dev/blog/vuln
func Vuln() error {
	fmt.Println("Vulnerability checks...")
	if err := installGoVulnIfNotPresent(); err != nil {
		fmt.Printf("Error installing go-vuln: %s", err.Error())
		return err
	}
	return sh.Run("govulncheck", "./...")
}

func installGoVulnIfNotPresent() error {
	return installIfNotPresent("govulncheck", "golang.org/x/vuln/cmd/govulncheck@latest")
}

// Clean deletes any build artifacts.
func Clean() {
	fmt.Println("Cleaning...")
	os.RemoveAll("bin")
}

// CleanRun removes Docker container, network, and image artifacts.
func CleanRun() error {
	if err := isDockerReady(); err != nil {
		return err
	}
	fmt.Println("Cleaning containers...")
	return sh.Run("docker-compose", "--project-directory", "build", "down", "--rmi", "local")
}

// Deps installs the dependencies needed for the build toolchain.
func Deps() error {
	return brewInstall("golangci-lint")
}

func brewInstall(formula string) error {
	return sh.Run("brew", "install", formula)
}

// Lint runs the configured linter.
func Lint() error {
	return sh.Run("golangci-lint", "run")
}

// Run the service via docker-compose.
func Run() error {
	if err := isDockerReady(); err != nil {
		return err
	}
	return sh.Run("docker-compose", "--project-directory", "build", "up", "--build")
}

// Test runs unit tests without coverage.
// The mage `-v` option will trigger a verbose output of the test
func Test() error {
	return runTests()
}

// CITest runs unit tests with coverage as a part of CI.
// The mage `-v` option will trigger a verbose output of the test
func CITest() error {
	return runCITests()
}

// Test runs unit tests without coverage.
// The mage `-v` option will trigger a verbose output of the test
func Integration() error {
	return runIntegrationTests()
}

// Spec generates an OpenAPI spec yaml based on code annotations.
func Spec() error {
	swagCommand := "swag"
	if err := installIfNotPresent(swagCommand, "github.com/swaggo/swag/cmd/swag@latest"); err != nil {
		logrus.Fatal(err)
		return err
	}
	// One of the dependencies we have (antlr4) does not play nicely with swaggo, but we need to enable dependencies
	// because many of our external API objects have ssi-sdk objects. We can work around this by setting depth. You can
	// see a discussion of this topic in https://github.com/swaggo/swag/issues/948.
	// We also set parseGoList because it's the only way parseDepth works until the following is fixed:
	// https://github.com/swaggo/swag/issues/1269
	return sh.Run(swagCommand, "init", "-g", "cmd/main.go", "--pd", "-o", "doc", "-ot", "yaml", "--parseDepth=3", "--parseGoList=false")
}

func runCITests(extraTestArgs ...string) error {
	args := []string{"test"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	args = append(args, "-tags=jwx_es256k")
	args = append(args, "-covermode=atomic")
	args = append(args, "-coverprofile=coverage.out")
	args = append(args, "-race")
	args = append(args, "-short")
	args = append(args, extraTestArgs...)
	args = append(args, "./...")
	testEnv := map[string]string{
		"CGO_ENABLED": "1",
		"GO111MODULE": "on",
	}
	writer := ColorizeTestStdout()
	fmt.Printf("%+v", args)
	_, err := sh.Exec(testEnv, writer, os.Stderr, Go, args...)
	return err
}

func runTests(extraTestArgs ...string) error {
	args := []string{"test"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	args = append(args, "-tags=jwx_es256k")
	args = append(args, "-short")
	args = append(args, extraTestArgs...)
	args = append(args, "./...")
	testEnv := map[string]string{
		"CGO_ENABLED": "1",
		"GO111MODULE": "on",
	}
	writer := ColorizeTestStdout()
	fmt.Printf("%+v", args)
	_, err := sh.Exec(testEnv, writer, os.Stderr, Go, args...)
	return err
}

func runIntegrationTests(extraTestArgs ...string) error {
	args := []string{"test"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	args = append(args, "-tags=jwx_es256k")
	args = append(args, extraTestArgs...)
	args = append(args, "./integration")
	testEnv := map[string]string{
		"CGO_ENABLED": "1",
		"GO111MODULE": "on",
	}
	writer := ColorizeTestStdout()
	fmt.Printf("%+v", args)
	_, err := sh.Exec(testEnv, writer, os.Stderr, Go, args...)
	return err
}

func ColorizeTestOutput(w io.Writer) io.Writer {
	writer := NewRegexpWriter(w, `PASS.*`, "\033[32m$0\033[0m")
	return NewRegexpWriter(writer, `FAIL.*`, "\033[31m$0\033[0m")
}

func ColorizeTestStdout() io.Writer {
	stdout := int(syscall.Stdout)
	if terminal.IsTerminal(stdout) {
		return ColorizeTestOutput(os.Stdout)
	}
	return os.Stdout
}

type regexpWriter struct {
	inner io.Writer
	re    *regexp.Regexp
	repl  []byte
}

func NewRegexpWriter(inner io.Writer, re string, repl string) io.Writer {
	return &regexpWriter{inner, regexp.MustCompile(re), []byte(repl)}
}

func (w *regexpWriter) Write(p []byte) (int, error) {
	r := w.re.ReplaceAll(p, w.repl)
	n, err := w.inner.Write(r)
	if n > len(r) {
		n = len(r)
	}
	return n, err
}

func runGo(cmd string, args ...string) error {
	return sh.Run(findOnPathOrGoPath("go"), append([]string{"run", cmd}, args...)...)
}

// InstallIfNotPresent installs a go based tool (if not already installed)
func installIfNotPresent(execName, goPackage string) error {
	usr, err := user.Current()
	if err != nil {
		logrus.WithError(err).Fatal()
		return err
	}
	pathOfExec := findOnPathOrGoPath(execName)
	if len(pathOfExec) == 0 {
		cmd := exec.Command(Go, "get", "-u", goPackage)
		if err := runGoCommand(usr, *cmd); err != nil {
			logrus.WithError(err).Warnf("Error running command: %s", cmd.String())
			cmd = exec.Command(Go, "install", goPackage)
			if err := runGoCommand(usr, *cmd); err != nil {
				logrus.WithError(err).Fatalf("Error running command: %s", cmd.String())
				return err
			}
		}
		logrus.Infof("Successfully installed %s", goPackage)
	}
	return nil
}

func runGoCommand(usr *user.User, cmd exec.Cmd) error {
	cmd.Dir = usr.HomeDir
	if err := cmd.Start(); err != nil {
		logrus.WithError(err).Fatalf("Error running command: %s", cmd.String())
		return err
	}
	return cmd.Wait()
}

// Check to see if Docker is running.
func isDockerReady() error {
	err := sh.Run("docker", "ps")
	if !sh.CmdRan(err) {
		return fmt.Errorf("could not run docker: %w", err)
	}
	return nil
}

func findOnPathOrGoPath(execName string) string {
	if p := findOnPath(execName); p != "" {
		return p
	}
	p := filepath.Join(goPath(), "bin", execName)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	fmt.Printf("Could not find %s on PATH or in GOPATH/bin\n", execName)
	return ""
}

func findOnPath(execName string) string {
	pathEnv := os.Getenv("PATH")
	pathDirectories := strings.Split(pathEnv, string(os.PathListSeparator))
	for _, pathDirectory := range pathDirectories {
		possible := filepath.Join(pathDirectory, execName)
		stat, err := os.Stat(possible)
		if err == nil || os.IsExist(err) {
			if (stat.Mode() & 0111) != 0 {
				return possible
			}
		}
	}
	return ""
}

func goPath() string {
	usr, err := user.Current()
	if err != nil {
		logrus.Fatal(err)
		return ""
	}
	goPath, goPathSet := os.LookupEnv("GOPATH")
	if !goPathSet {
		goPath = filepath.Join(usr.HomeDir, Go)
	}
	return goPath
}

// CBT runs clean; build; test.
func CBT() error {
	Clean()
	if err := Build(); err != nil {
		return err
	}
	if err := Lint(); err != nil {
		return err
	}
	if err := Test(); err != nil {
		return err
	}
	return nil
}

/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

package exec

import (
	"context"
	"io"
	osexec "os/exec"
	"syscall"
	"time"
)

// ErrExecutableNotFound is returned if the executable is not found.
var ErrExecutableNotFound = osexec.ErrNotFound

// Interface is an interface that presents a subset of the os/exec API.  Use this
// when you want to inject fakeable/mockable exec behavior.
type Interface interface {
	// Command returns a Cmd instance which can be used to run a single command.
	// This follows the pattern of package os/exec.
	Command(cmd string, args ...string) Cmd
	CommandContext(ctx context.Context, cmd string, args ...string) Cmd

	// LookPath wraps os/exec.LookPath
	LookPath(file string) (string, error)
}

// Cmd is an interface that presents an API that is very similar to Cmd from os/exec.
// As more functionality is needed, this can grow.  Since Cmd is a struct, we will have
// to replace fields with get/set method pairs.
type Cmd interface {
	// CombinedOutput runs the command and returns its combined standard output
	// and standard error.  This follows the pattern of package os/exec.
	CombinedOutput() ([]byte, error)
	// Output runs the command and returns standard output, but not standard err
	Output() ([]byte, error)
	SetDir(dir string)
	SetStdin(in io.Reader)
	SetStdout(out io.Writer)
}

// ExitError is an interface that presents an API similar to os.ProcessState, which is
// what ExitError from os/exec is.  This is designed to make testing a bit easier and
// probably loses some of the cross-platform properties of the underlying library.
type ExitError interface {
	String() string
	Error() string
	Exited() bool
	ExitStatus() int
}

// Implements Interface in terms of really exec()ing.
type executor struct{}

// New returns a new Interface which will os/exec to run commands.
func New() Interface {
	return &executor{}
}

// Command is part of the Interface interface.
func (executor *executor) Command(cmd string, args ...string) Cmd {
	// default to a 30s timeout if the user calls a normal Command.  Running normal Command without
	// a context is not safe
	ctx, ctxCancel := context.WithTimeout(context.Background(), time.Second*30)
	defer ctxCancel()
	return (*cmdWrapper)(osexec.CommandContext(ctx, cmd, args...))
}

// CommandContext is part of the Interface interface.
func (executor *executor) CommandContext(ctx context.Context, cmd string, args ...string) Cmd {
	return (*cmdWrapper)(osexec.CommandContext(ctx, cmd, args...))
}

// LookPath is part of the Interface interface
func (executor *executor) LookPath(file string) (string, error) {
	return osexec.LookPath(file)
}

// Wraps exec.Cmd so we can capture errors.
type cmdWrapper osexec.Cmd

func (cmd *cmdWrapper) SetDir(dir string) {
	cmd.Dir = dir
}

func (cmd *cmdWrapper) SetStdin(in io.Reader) {
	cmd.Stdin = in
}

func (cmd *cmdWrapper) SetStdout(out io.Writer) {
	cmd.Stdout = out
}

// CombinedOutput is part of the Cmd interface.
func (cmd *cmdWrapper) CombinedOutput() ([]byte, error) {
	out, err := (*osexec.Cmd)(cmd).CombinedOutput()
	if err != nil {
		return out, handleError(err)
	}
	return out, nil
}

func (cmd *cmdWrapper) Output() ([]byte, error) {
	out, err := (*osexec.Cmd)(cmd).Output()
	if err != nil {
		return out, handleError(err)
	}
	return out, nil
}

func handleError(err error) error {
	if ee, ok := err.(*osexec.ExitError); ok {
		// Force a compile fail if exitErrorWrapper can't convert to ExitError.
		var x ExitError = &ExitErrorWrapper{ee}
		return x
	}
	if ee, ok := err.(*osexec.Error); ok {
		if ee.Err == osexec.ErrNotFound {
			return ErrExecutableNotFound
		}
	}
	return err
}

// ExitErrorWrapper is an implementation of ExitError in terms of os/exec ExitError.
// Note: standard exec.ExitError is type *os.ProcessState, which already implements Exited().
type ExitErrorWrapper struct {
	*osexec.ExitError
}

var _ ExitError = ExitErrorWrapper{}

// ExitStatus is part of the ExitError interface.
func (eew ExitErrorWrapper) ExitStatus() int {
	ws, ok := eew.Sys().(syscall.WaitStatus)
	if !ok {
		panic("can't call ExitStatus() on a non-WaitStatus exitErrorWrapper")
	}
	return ws.ExitStatus()
}

// CodeExitError is an implementation of ExitError consisting of an error object
// and an exit code (the upper bits of os.exec.ExitStatus).
type CodeExitError struct {
	Err  error
	Code int
}

var _ ExitError = CodeExitError{}

func (e CodeExitError) Error() string {
	return e.Err.Error()
}

func (e CodeExitError) String() string {
	return e.Err.Error()
}

func (e CodeExitError) Exited() bool {
	return true
}

func (e CodeExitError) ExitStatus() int {
	return e.Code
}

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// Decrypt runs gpg --decrypt on the given file and returns the plaintext.
// The returned buffer is locked against swap (see lock); callers must zero
// and unlock it once they're done.
func Decrypt(path string) ([]byte, error) {
	cmd := exec.Command("gpg", "--decrypt", "--quiet", path)
	cmd.Stdin = os.Stdin // allows pinentry to prompt if needed
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg decrypt failed: %w\n%s", err, errBuf.String())
	}
	plaintext := out.Bytes()
	lock(plaintext)
	return plaintext, nil
}

// Encrypt encrypts plaintext to path (ASCII-armored) for all recipients.
func Encrypt(plaintext []byte, path string, recipients []string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured; run 'arruin init' first")
	}

	args := []string{"--encrypt", "--armor", "--yes", "--output", path}
	for _, r := range recipients {
		args = append(args, "--recipient", r)
	}

	cmd := exec.Command("gpg", args...)
	cmd.Stdin = bytes.NewReader(plaintext)
	cmd.Stdout = os.Stdout
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gpg encrypt failed: %w\n%s", err, errBuf.String())
	}
	return nil
}

// newMemFile creates an anonymous, memory-only file (Linux memfd_create)
// and wraps it as an *os.File. Unlike a real temp file, it has no path on
// any filesystem -- nothing for `ls` to show and nothing to shred -- and
// its memory is reclaimed unconditionally as soon as every reference to it
// is closed, including on a crash or SIGKILL. MFD_CLOEXEC keeps the fd
// from being inherited by gpg or other children spawned afterward; it's
// handed to the editor explicitly via cmd.ExtraFiles instead.
func newMemFile(name string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// zero overwrites b with zero bytes. Best-effort: it shrinks the window a
// decrypted secret sits live in memory once we're done with it, but Go
// gives no guarantee against stale copies left by buffer growth or GC, nor
// against the bytes having already reached swap before this runs.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// lock mlocks b's backing memory so the kernel cannot page it to swap while
// the secret it holds is in use. Best-effort: a failure (e.g. a low
// RLIMIT_MEMLOCK) is reported but does not abort the operation, and it does
// nothing for any copy already made before lock was called.
func lock(b []byte) {
	if len(b) == 0 {
		return
	}
	if err := syscall.Mlock(b); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not lock memory against swap: %v\n", err)
	}
}

// unlock reverses lock. It does not itself clear b -- call zero first.
func unlock(b []byte) {
	if len(b) == 0 {
		return
	}
	if err := syscall.Munlock(b); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not unlock memory: %v\n", err)
	}
}

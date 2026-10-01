package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const usage = `Ár Rúin -- local encrypted secrets manager

Usage:
  arruin [--db <path>] <command> [args]

Commands:
  init                        Configure recipients and db path
  list                        List all sites
  get    <site>               Print entry for site
  add    <site> <user> <pass> Add a new entry
  update <site> <user> <pass> Update entry (rotates current password to old)
  delete <site>               Delete entry
  edit                        Decrypt to an in-memory file, open $EDITOR, re-encrypt

Flags:
  --db <path>   Path to encrypted secrets file (overrides config)
`

func main() {
	disableCoreDumps()
	disableDumpable()

	dbFlag := flag.String("db", "", "path to encrypted secrets file")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	cfg, err := LoadConfig()
	if err != nil {
		fatal("loading config: %v", err)
	}
	dbPath := cfg.ResolvedDBPath(*dbFlag)

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "init":
		cmdInit(cfg)
	case "list":
		cmdList(dbPath)
	case "get":
		requireArgs(cmd, rest, 1)
		cmdGet(dbPath, rest[0])
	case "add":
		requireArgs(cmd, rest, 3)
		cmdAdd(dbPath, cfg, rest[0], rest[1], rest[2])
	case "update":
		requireArgs(cmd, rest, 3)
		cmdUpdate(dbPath, cfg, rest[0], rest[1], rest[2])
	case "delete":
		requireArgs(cmd, rest, 1)
		cmdDelete(dbPath, cfg, rest[0])
	case "edit":
		cmdEdit(dbPath, cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", cmd)
		flag.Usage()
		os.Exit(1)
	}
}

// cmdInit interactively configures recipients and db path, then saves config.
func cmdInit(cfg *Config) {
	r := bufio.NewReader(os.Stdin)

	fmt.Println("Configure Ár Rúin")
	fmt.Println()

	// Recipients
	fmt.Println("Enter GPG recipient key IDs or fingerprints, one per line.")
	fmt.Println("Leave blank and press Enter when done.")
	var recipients []string
	for {
		fmt.Print("Recipient: ")
		line, _ := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		recipients = append(recipients, line)
	}
	if len(recipients) == 0 {
		fatal("at least one recipient is required")
	}
	cfg.Recipients = recipients

	// DB path
	fmt.Printf("DB file path [%s]: ", defaultDBName)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line != "" {
		cfg.DBPath = line
	}

	if err := SaveConfig(cfg); err != nil {
		fatal("saving config: %v", err)
	}

	dbPath := cfg.ResolvedDBPath("")

	// Create an empty db if it doesn't already exist.
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		if err := Encrypt([]byte{}, dbPath, cfg.Recipients); err != nil {
			fatal("creating empty db: %v", err)
		}
		fmt.Printf("Created empty secrets file at %s\n", dbPath)
	}

	fmt.Println("Done.")
}

func cmdList(dbPath string) {
	db := mustLoadDB(dbPath)
	entries := db.Entries()
	if len(entries) == 0 {
		fmt.Println("(no entries)")
		return
	}
	for _, e := range entries {
		fmt.Println(e.Site)
	}
}

func cmdGet(dbPath, site string) {
	db := mustLoadDB(dbPath)
	e, ok := db.Get(site)
	if !ok {
		fatal("no entry found for %q", site)
	}
	fmt.Println(e)
}

func cmdAdd(dbPath string, cfg *Config, site, user, pass string) {
	db := mustLoadDB(dbPath)
	if err := db.Add(Entry{Site: site, User: user, Password: pass}); err != nil {
		fatal("%v", err)
	}
	mustSaveDB(db, dbPath, cfg)
	fmt.Printf("Added %s\n", site)
}

func cmdUpdate(dbPath string, cfg *Config, site, user, pass string) {
	db := mustLoadDB(dbPath)
	if err := db.Update(site, user, pass); err != nil {
		fatal("%v", err)
	}
	mustSaveDB(db, dbPath, cfg)
	fmt.Printf("Updated %s\n", site)
}

func cmdDelete(dbPath string, cfg *Config, site string) {
	db := mustLoadDB(dbPath)
	if err := db.Delete(site); err != nil {
		fatal("%v", err)
	}
	mustSaveDB(db, dbPath, cfg)
	fmt.Printf("Deleted %s\n", site)
}

func cmdEdit(dbPath string, cfg *Config) {
	// Decrypt into an anonymous, memory-only file so the editor has
	// something file-shaped to open without arruin ever creating a
	// cleartext file on disk. Its memory is reclaimed unconditionally when
	// the process exits -- even on a crash or Ctrl-C -- so unlike a real
	// temp file there's no cleanup step that can be skipped.
	memFile, err := newMemFile("arruin-secrets")
	if err != nil {
		fatal("creating in-memory file: %v", err)
	}
	defer memFile.Close()

	plaintext, err := Decrypt(dbPath)
	if err != nil {
		fatal("%v", err)
	}
	if _, err := memFile.Write(plaintext); err != nil {
		zero(plaintext)
		unlock(plaintext)
		fatal("writing to in-memory file: %v", err)
	}
	zero(plaintext)
	unlock(plaintext)

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	// memFile is inherited by the child as fd 3 (the first ExtraFiles
	// entry); /proc/self/fd/3 resolves relative to the editor's own
	// process, not arruin's.
	editorCmd := exec.Command(editor, "/proc/self/fd/3")
	editorCmd.ExtraFiles = []*os.File{memFile}
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		fatal("editor exited with error: %v", err)
	}

	if _, err := memFile.Seek(0, io.SeekStart); err != nil {
		fatal("seeking in-memory file: %v", err)
	}
	edited, err := io.ReadAll(memFile)
	if err != nil {
		fatal("reading edited content: %v", err)
	}
	lock(edited)
	if err := Encrypt(edited, dbPath, cfg.Recipients); err != nil {
		zero(edited)
		unlock(edited)
		fatal("%v", err)
	}
	zero(edited)
	unlock(edited)
	fmt.Println("Saved.")
}

// mustLoadDB decrypts and parses the db file, exiting on any error.
func mustLoadDB(dbPath string) *DB {
	plaintext, err := Decrypt(dbPath)
	if err != nil {
		fatal("%v", err)
	}
	defer unlock(plaintext)
	defer zero(plaintext)
	return ParseDB(plaintext)
}

// mustSaveDB serialises and encrypts the db, exiting on any error.
func mustSaveDB(db *DB, dbPath string, cfg *Config) {
	serialised := db.Serialise()
	lock(serialised)
	// fatal's os.Exit would skip a deferred zero/unlock, so both are called
	// explicitly on every exit path instead.
	if err := Encrypt(serialised, dbPath, cfg.Recipients); err != nil {
		zero(serialised)
		unlock(serialised)
		fatal("saving db: %v", err)
	}
	zero(serialised)
	unlock(serialised)
}

// disableCoreDumps prevents a crash from writing process memory -- which may
// contain decrypted secrets -- to disk as a core dump.
func disableCoreDumps() {
	limit := syscall.Rlimit{Cur: 0, Max: 0}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &limit); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not disable core dumps: %v\n", err)
	}
}

// disableDumpable marks the process non-dumpable (Linux prctl
// PR_SET_DUMPABLE), which, beyond suppressing core dumps, also stops other
// processes from ptrace-attaching or reading /proc/<pid>/mem while arruin
// is holding decrypted secrets. The same mechanism gpg-agent and ssh-agent
// use. Unlike RLIMIT_CORE, this flag resets on execve, so it does not carry
// over to the gpg/shred/$EDITOR child processes arruin spawns.
func disableDumpable() {
	const prSetDumpable = 4 // linux/prctl.h
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		fmt.Fprintf(os.Stderr, "warning: could not mark process non-dumpable: %v\n", errno)
	}
}

func requireArgs(cmd string, args []string, n int) {
	if len(args) < n {
		fmt.Fprintf(os.Stderr, "%s requires %d argument(s)\n\n", cmd, n)
		flag.Usage()
		os.Exit(1)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
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
  edit                        Decrypt to temp file, open $EDITOR, re-encrypt, shred

Flags:
  --db <path>   Path to encrypted secrets file (overrides config)
`

func main() {
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
	// Decrypt to a temp file in a mode-700 temp dir.
	tmpDir, err := os.MkdirTemp("", "arruin-*")
	if err != nil {
		fatal("creating temp dir: %v", err)
	}

	// cleanup shreds anything left in tmpDir and removes it. It's called
	// explicitly on every exit path below (not just deferred), because
	// fatal() calls os.Exit, which skips deferred functions.
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			entries, _ := os.ReadDir(tmpDir)
			for _, ent := range entries {
				_ = Shred(filepath.Join(tmpDir, ent.Name()))
			}
			_ = os.Remove(tmpDir)
		})
	}
	defer cleanup()

	// bail cleans up before handing off to fatal, since fatal's os.Exit
	// would otherwise skip the deferred cleanup above.
	bail := func(format string, a ...any) {
		cleanup()
		fatal(format, a...)
	}

	// Without a handler, SIGINT/SIGTERM (e.g. Ctrl-C while the editor is
	// open) terminates the process immediately and skips the deferred
	// cleanup, leaving decrypted plaintext on disk. Intercept and clean up
	// first.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		if _, ok := <-sigCh; ok {
			cleanup()
			os.Exit(1)
		}
	}()

	if err := os.Chmod(tmpDir, 0700); err != nil {
		bail("chmod temp dir: %v", err)
	}

	tmpFile := filepath.Join(tmpDir, "secrets.txt")

	plaintext, err := Decrypt(dbPath)
	if err != nil {
		bail("%v", err)
	}
	if err := os.WriteFile(tmpFile, plaintext, 0600); err != nil {
		bail("writing temp file: %v", err)
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	editorCmd := exec.Command(editor, tmpFile)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		bail("editor exited with error: %v", err)
	}

	edited, err := os.ReadFile(tmpFile)
	if err != nil {
		bail("reading edited file: %v", err)
	}
	if err := Encrypt(edited, dbPath, cfg.Recipients); err != nil {
		bail("%v", err)
	}
	// Shred is handled by the deferred cleanup above.
	fmt.Println("Saved.")
}

// mustLoadDB decrypts and parses the db file, exiting on any error.
func mustLoadDB(dbPath string) *DB {
	plaintext, err := Decrypt(dbPath)
	if err != nil {
		fatal("%v", err)
	}
	return ParseDB(plaintext)
}

// mustSaveDB serialises and encrypts the db, exiting on any error.
func mustSaveDB(db *DB, dbPath string, cfg *Config) {
	if err := Encrypt(db.Serialise(), dbPath, cfg.Recipients); err != nil {
		fatal("saving db: %v", err)
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

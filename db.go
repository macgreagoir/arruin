package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// Entry represents a single password record:  site user password [oldpassword]
type Entry struct {
	Site        string
	User        string
	Password    string
	OldPassword string // optional
}

func (e Entry) String() string {
	if e.OldPassword != "" {
		return fmt.Sprintf("%s %s %s %s", e.Site, e.User, e.Password, e.OldPassword)
	}
	return fmt.Sprintf("%s %s %s", e.Site, e.User, e.Password)
}

// DB holds structured password entries and unmanaged (schemaless) lines.
// Unmanaged lines are preserved verbatim so a round-trip does not destroy them.
type DB struct {
	lines []dbLine // ordered, preserves original structure
}

type lineKind int

const (
	kindEntry    lineKind = iota
	kindVerbatim          // blank lines, comments, or multiline schemaless content
)

type dbLine struct {
	kind  lineKind
	entry Entry  // valid when kind == kindEntry
	raw   string // valid when kind == kindVerbatim
}

// ParseDB parses the decrypted plaintext of the secrets file.
// Lines that look like "site user password [oldpassword]" become entries.
// Everything else is kept verbatim.
func ParseDB(data []byte) *DB {
	db := &DB{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if e, ok := parseEntry(line); ok {
			db.lines = append(db.lines, dbLine{kind: kindEntry, entry: e})
		} else {
			db.lines = append(db.lines, dbLine{kind: kindVerbatim, raw: line})
		}
	}
	return db
}

// parseEntry attempts to parse a line as a password entry.
// A valid entry has exactly 3 or 4 space-separated fields where none are blank.
func parseEntry(line string) (Entry, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return Entry{}, false
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 3 || len(fields) > 4 {
		return Entry{}, false
	}
	e := Entry{
		Site:     fields[0],
		User:     fields[1],
		Password: fields[2],
	}
	if len(fields) == 4 {
		e.OldPassword = fields[3]
	}
	return e, true
}

// Serialise returns the plaintext representation of the DB.
func (db *DB) Serialise() []byte {
	var buf bytes.Buffer
	for _, l := range db.lines {
		switch l.kind {
		case kindEntry:
			buf.WriteString(l.entry.String())
		case kindVerbatim:
			buf.WriteString(l.raw)
		}
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// Entries returns all structured password entries.
func (db *DB) Entries() []Entry {
	var out []Entry
	for _, l := range db.lines {
		if l.kind == kindEntry {
			out = append(out, l.entry)
		}
	}
	return out
}

// Get returns the first entry matching site (case-insensitive).
func (db *DB) Get(site string) (Entry, bool) {
	site = strings.ToLower(site)
	for _, l := range db.lines {
		if l.kind == kindEntry && strings.ToLower(l.entry.Site) == site {
			return l.entry, true
		}
	}
	return Entry{}, false
}

// Add appends a new entry. Returns an error if the site already exists.
func (db *DB) Add(e Entry) error {
	if _, exists := db.Get(e.Site); exists {
		return fmt.Errorf("entry for %q already exists; use 'update' to change it", e.Site)
	}
	db.lines = append(db.lines, dbLine{kind: kindEntry, entry: e})
	return nil
}

// Update replaces the entry for the given site, rotating the current password
// into OldPassword. Returns an error if the site does not exist.
func (db *DB) Update(site, user, password string) error {
	site = strings.ToLower(site)
	for i, l := range db.lines {
		if l.kind == kindEntry && strings.ToLower(l.entry.Site) == site {
			if l.entry.Password == password {
				return fmt.Errorf("new password is the same as the current password for %q", site)
			}
			old := fmt.Sprintf("(%s)", l.entry.Password)
			db.lines[i].entry.User = user
			db.lines[i].entry.OldPassword = old
			db.lines[i].entry.Password = password
			return nil
		}
	}
	return fmt.Errorf("no entry found for %q", site)
}

// Delete removes the entry for the given site. Returns an error if not found.
func (db *DB) Delete(site string) error {
	site = strings.ToLower(site)
	for i, l := range db.lines {
		if l.kind == kindEntry && strings.ToLower(l.entry.Site) == site {
			db.lines = append(db.lines[:i], db.lines[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no entry found for %q", site)
}

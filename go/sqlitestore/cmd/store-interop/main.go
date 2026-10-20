// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

// Command store-interop drives a profile's store from Go for spec/store's interoperability
// matrix (spec/store/interop/run.sh): the profile comes from TI_PROFILE, TI_STATE_DIR,
// TI_CACHE_DIR, TI_STORE_KEK_PATH and TI_STORE_BACKEND as for every TI tool; ti's
// examples/store-interop takes the same arguments.
//
//	store-interop put NS ID PAYLOAD [FIELD=VALUE ...]
//	store-interop get NS ID          # the payload; exit 3 if there is none
//	store-interop take NS ID         # the same, and the record is gone
//	store-interop query NS FIELD=VALUE ...   # the number of records
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/sqlitestore"
	"github.com/gematik/zero-lab/go/store"
	"github.com/gematik/zero-lab/go/store/filestore"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "store-interop: %s: %v\n", store.CodeOf(err), err)
		if errors.Is(err, store.ErrNotFound) {
			os.Exit(3)
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: store-interop put|get|take|query NS [ARGS]")
	}
	op, nsName := args[0], args[1]
	var ns store.Namespace
	for _, n := range store.Registry() {
		if n.Name == nsName {
			ns = n
		}
	}
	if ns.Name == "" {
		return fmt.Errorf("no namespace %q", nsName)
	}
	ctx := context.Background()
	s, closeStore, err := open(ctx, ns)
	if err != nil {
		return err
	}
	defer closeStore()
	now := time.Now()
	switch {
	case op == "put" && len(args) >= 4:
		meta, err := metadata(args[4:])
		if err != nil {
			return err
		}
		var expires time.Time
		if ns.MaxTTL > 0 {
			expires = now.Add(time.Duration(ns.MaxTTL) * time.Second)
		}
		_, err = s.Put(ctx, ns, []byte(args[2]), []byte(args[3]), meta, expires, now)
		return err
	case (op == "get" || op == "take") && len(args) == 3:
		get := s.Get
		if op == "take" {
			get = s.Take
		}
		r, err := get(ctx, ns, []byte(args[2]), now)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(r.Payload)
		return err
	case op == "query":
		meta, err := metadata(args[2:])
		if err != nil {
			return err
		}
		n := 0
		var cursor *store.Name
		for {
			page, next, err := s.Query(ctx, ns, meta, 1000, cursor, now)
			if err != nil {
				return err
			}
			n += len(page)
			if next == nil {
				break
			}
			cursor = next
		}
		fmt.Println(n)
		return nil
	}
	return fmt.Errorf("unknown or incomplete operation %q", op)
}

func metadata(args []string) ([]store.Meta, error) {
	var meta []store.Meta
	for _, a := range args {
		field, value, ok := strings.Cut(a, "=")
		if !ok {
			return nil, fmt.Errorf("metadata %q is not FIELD=VALUE", a)
		}
		meta = append(meta, store.Meta{Field: field, Value: []byte(value)})
	}
	return meta, nil
}

// open resolves the profile as every TI tool does and opens the database ns lives in,
// with the profile's keyring if it has one.
func open(ctx context.Context, ns store.Namespace) (*store.Store, func(), error) {
	home, _ := os.UserHomeDir()
	platform := store.CurrentPlatform()
	var active *string
	if path := store.ActiveFile(platform, os.LookupEnv, home); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			s := string(b)
			active = &s
		}
	}
	p, err := store.ResolveProfile(store.ProfileInputs{
		Platform: platform, LookupEnv: os.LookupEnv, Active: active, Home: home,
	})
	if err != nil {
		return nil, nil, err
	}
	files := os.Getenv("TI_STORE_BACKEND") == "files"
	var backend store.Backend
	var closeBackend func() error
	switch {
	case files:
		root := p.StateRoot
		if ns.Database == store.CacheDB {
			root = p.CacheRoot
		}
		b, err := filestore.Open(root)
		if err != nil {
			return nil, nil, err
		}
		backend, closeBackend = b, b.Close
	default:
		path, kind := p.StateDB, sqlitestore.State
		if ns.Database == store.CacheDB {
			path, kind = p.CacheDB, sqlitestore.Cache
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, nil, err
		}
		b, err := sqlitestore.Open(ctx, path, kind)
		if err != nil {
			return nil, nil, err
		}
		backend, closeBackend = b, b.Close
	}
	sealer, err := keyring(ctx, p)
	if err != nil {
		_ = closeBackend()
		return nil, nil, err
	}
	var namespaces []store.Namespace
	for _, n := range store.Registry() {
		if n.Database == ns.Database {
			namespaces = append(namespaces, n)
		}
	}
	s, err := store.New(backend, sealer, namespaces)
	if err != nil {
		_ = closeBackend()
		return nil, nil, err
	}
	return s, func() { _ = closeBackend() }, nil
}

// keyring is the profile's keyring unwrapped with its key file, or nil without one.
func keyring(ctx context.Context, p store.Profile) (store.Sealer, error) {
	raw, err := os.ReadFile(p.Keyring)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f, err := store.ParseKeyringFile(raw)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(p.KEKFile)
	if err != nil {
		return nil, err
	}
	mode := -1
	if runtime.GOOS != "windows" {
		info, err := os.Stat(p.KEKFile)
		if err != nil {
			return nil, err
		}
		mode = int(info.Mode().Perm())
	}
	kek, err := store.ParseKEKFile(content, mode)
	if err != nil {
		return nil, err
	}
	return store.OpenKeyring(ctx, f, store.NewKeyFileWrapper(kek, rand.Reader), rand.Reader)
}

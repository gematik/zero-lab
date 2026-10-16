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

package store

import (
	"runtime"
	"strings"
)

// Platform decides how paths are written and which defaults apply (STORE-092).
type Platform int

const (
	// Unix is Linux, macOS and other Unix systems: the XDG layout.
	Unix Platform = iota
	// Windows uses the local and roaming application data.
	Windows
)

// CurrentPlatform is the platform this program runs on.
func CurrentPlatform() Platform {
	if runtime.GOOS == "windows" {
		return Windows
	}
	return Unix
}

func (p Platform) abs(s string) bool {
	if p == Windows {
		return strings.HasPrefix(s, `\\`) || (len(s) >= 3 && ((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) && s[1] == ':' && s[2] == '\\')
	}
	return strings.HasPrefix(s, "/")
}

func (p Platform) join(parts ...string) string {
	if p == Windows {
		return strings.Join(parts, `\`)
	}
	return strings.Join(parts, "/")
}

// ProfileInputs is what resolution reads, handed in by the caller.
type ProfileInputs struct {
	Platform Platform
	// Flag is --profile, or nil.
	Flag *string
	// LookupEnv is os.LookupEnv or a stand-in.
	LookupEnv func(string) (string, bool)
	// Active is the content of the active file, or nil if it does not exist.
	Active *string
	// Home is the home directory, or empty.
	Home string
}

// Profile is the profile in effect and its files (STORE-091 to STORE-094).
type Profile struct {
	Name string
	// From is flag, env, active or default.
	From       string
	ActiveFile string
	KEKFile    string
	Keyring    string
	StateDB    string
	CacheDB    string
	StateRoot  string
	CacheRoot  string
}

// ValidProfileName reports whether name has the syntax of STORE-090.
func ValidProfileName(name string) bool {
	if len(name) < 1 || len(name) > 32 || (!lower(name[0]) && !digit(name[0])) {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !lower(c) && !digit(c) && c != '-' {
			return false
		}
	}
	return true
}

type resolver struct{ in *ProfileInputs }

func (r resolver) env(k string) (string, bool) {
	if r.in.LookupEnv == nil {
		return "", false
	}
	return r.in.LookupEnv(k)
}

func (r resolver) xdg(name string, fallback ...string) (string, error) {
	if v, _ := r.env(name); v != "" && r.in.Platform.abs(v) {
		return v, nil
	}
	if r.in.Home == "" || !r.in.Platform.abs(r.in.Home) {
		return "", fail(CodeInvalidArgument, "home directory")
	}
	return r.in.Platform.join(append([]string{r.in.Home}, fallback...)...), nil
}

func (r resolver) appData(name string) (string, error) {
	if v, _ := r.env(name); v != "" && r.in.Platform.abs(v) {
		return v, nil
	}
	return "", fail(CodeInvalidArgument, "application data directory")
}

// explicit is TI_STATE_DIR and friends: absolute if set.
func (r resolver) explicit(name string) (string, bool, error) {
	v, ok := r.env(name)
	if !ok {
		return "", false, nil
	}
	if v == "" || !r.in.Platform.abs(v) {
		return "", true, fail(CodeInvalidArgument, name)
	}
	return v, true, nil
}

func (r resolver) config() (string, error) {
	if r.in.Platform == Windows {
		return r.appData("APPDATA")
	}
	return r.xdg("XDG_CONFIG_HOME", ".config")
}

func (r resolver) base(override, xdgVar string, xdgFallback []string, windowsParts ...string) (string, error) {
	if v, ok, err := r.explicit(override); ok || err != nil {
		return v, err
	}
	p := r.in.Platform
	if p == Windows {
		local, err := r.appData("LOCALAPPDATA")
		if err != nil {
			return "", err
		}
		return p.join(append([]string{local}, windowsParts...)...), nil
	}
	b, err := r.xdg(xdgVar, xdgFallback...)
	if err != nil {
		return "", err
	}
	return p.join(b, "telematik"), nil
}

// ActiveFile is the active file of STORE-091, or empty if the configuration directory is
// unknown. The caller reads it and passes its content as [ProfileInputs.Active].
func ActiveFile(p Platform, lookupEnv func(string) (string, bool), home string) string {
	r := resolver{&ProfileInputs{Platform: p, LookupEnv: lookupEnv, Home: home}}
	c, err := r.config()
	if err != nil {
		return ""
	}
	return p.join(c, "telematik", "profiles", "active")
}

// ResolveProfile applies STORE-091 to STORE-094.
func ResolveProfile(in ProfileInputs) (Profile, error) {
	r := resolver{&in}
	p := in.Platform
	var name, from string
	switch {
	case in.Flag != nil:
		name, from = *in.Flag, "flag"
	default:
		if v, _ := r.env("TI_PROFILE"); v != "" {
			name, from = v, "env"
		} else if in.Active != nil {
			line, _, _ := strings.Cut(*in.Active, "\n")
			if line = strings.TrimSuffix(line, "\r"); line != "" {
				name, from = line, "active"
			}
		}
		if name == "" {
			name, from = "default", "default"
		}
	}
	// never a fall-through to the next source
	if !ValidProfileName(name) {
		return Profile{}, fail(CodeInvalidArgument, "profile name")
	}
	config, configErr := r.config()
	state, err := r.base("TI_STATE_DIR", "XDG_STATE_HOME", []string{".local", "state"}, "state", "telematik")
	if err != nil {
		return Profile{}, err
	}
	cache, err := r.base("TI_CACHE_DIR", "XDG_CACHE_HOME", []string{".cache"}, "telematik")
	if err != nil {
		return Profile{}, err
	}
	kek, ok, err := r.explicit("TI_STORE_KEK_PATH")
	if err != nil {
		return Profile{}, err
	}
	if !ok {
		if configErr != nil {
			return Profile{}, configErr
		}
		kek = p.join(config, "telematik", "profiles", name, "store.kek")
	}
	active := ""
	if configErr == nil {
		active = p.join(config, "telematik", "profiles", "active")
	}
	stateDir, cacheDir := p.join(state, "profiles", name), p.join(cache, "profiles", name)
	return Profile{
		Name: name, From: from, ActiveFile: active, KEKFile: kek,
		Keyring:   p.join(stateDir, "keyring.bin"),
		StateDB:   p.join(stateDir, "state.db"),
		CacheDB:   p.join(cacheDir, "cache.db"),
		StateRoot: p.join(stateDir, "state"),
		CacheRoot: p.join(cacheDir, "cache"),
	}, nil
}

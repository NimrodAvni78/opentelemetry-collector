// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package builder // import "go.opentelemetry.io/collector/cmd/builder/internal/builder"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"go.uber.org/multierr"
	"go.uber.org/zap"
)

const (
	DefaultBetaOtelColVersion   = "v0.153.0"
	DefaultStableOtelColVersion = "v1.59.0"
)

// errMissingGoMod indicates an empty gomod field
var errMissingGoMod = errors.New("missing gomod specification for module")

// Config holds the builder's configuration
type Config struct {
	Logger *zap.Logger `mapstructure:"-"`

	OtelColVersion       string `mapstructure:"-"` // only used be the go.mod template
	SkipGenerate         bool   `mapstructure:"-"`
	SkipCompilation      bool   `mapstructure:"-"`
	SkipGetModules       bool   `mapstructure:"-"`
	SkipStrictVersioning bool   `mapstructure:"-"`
	LDFlags              string `mapstructure:"-"`
	LDSet                bool   `mapstructure:"-"` // only used to override LDFlags
	GCFlags              string `mapstructure:"-"`
	GCSet                bool   `mapstructure:"-"` // only used to override GCFlags
	Verbose              bool   `mapstructure:"-"`

	Distribution      Distribution `mapstructure:"dist"`
	Exporters         []Module     `mapstructure:"exporters,omitempty"`
	Extensions        []Module     `mapstructure:"extensions,omitempty"`
	Receivers         []Module     `mapstructure:"receivers,omitempty"`
	Processors        []Module     `mapstructure:"processors,omitempty"`
	Connectors        []Module     `mapstructure:"connectors,omitempty"`
	Telemetry         Module       `mapstructure:"telemetry,omitempty"`
	ConfmapProviders  []Module     `mapstructure:"providers,omitempty"`
	ConfmapConverters []Module     `mapstructure:"converters,omitempty"`
	Replaces          []string     `mapstructure:"replaces,omitempty"`
	Excludes          []string     `mapstructure:"excludes,omitempty"`

	ConfResolver ConfResolver `mapstructure:"conf_resolver,omitempty"`

	// DownloadCacheDir overrides the root directory used to cache downloaded
	// source archives. When empty, a default under os.UserCacheDir() is used.
	DownloadCacheDir string `mapstructure:"download_cache_dir,omitempty"`

	downloadModules retry `mapstructure:"-"`

	// sourceArchiveCacheRoot overrides the resolved source archive cache root.
	// It is only set in tests to avoid writing to the real user cache dir.
	sourceArchiveCacheRoot string `mapstructure:"-"`

	// httpClient is the HTTP client used to download source archives. When nil,
	// a default client with a sane timeout is used. It is only set in tests.
	httpClient *http.Client `mapstructure:"-"`
}

type ConfResolver struct {
	// When set, will be used to set the CollectorSettings.ConfResolver.DefaultScheme value,
	// which determines how the Collector interprets URIs that have no scheme, such as ${ENV}.
	// See https://pkg.go.dev/go.opentelemetry.io/collector/confmap#ResolverSettings for more details.
	DefaultURIScheme string `mapstructure:"default_uri_scheme,omitempty"`
}

// Distribution holds the parameters for the final binary
type Distribution struct {
	Module                  string `mapstructure:"module,omitempty"`
	Name                    string `mapstructure:"name"`
	Go                      string `mapstructure:"go,omitempty"`
	Description             string `mapstructure:"description"`
	OutputPath              string `mapstructure:"output_path"`
	Version                 string `mapstructure:"version,omitempty"`
	BuildTags               string `mapstructure:"build_tags,omitempty"`
	DebugCompilation        bool   `mapstructure:"debug_compilation,omitempty"`
	CGoEnabled              bool   `mapstructure:"cgo_enabled,omitempty"`
	UseAbsoluteReplacePaths bool   `mapstructure:"use_absolute_replace_paths,omitempty"`
}

// Module represents a receiver, exporter, processor or extension for the distribution
type Module struct {
	Name          string         `mapstructure:"name,omitempty"`           // if not specified, this is package part of the go mod (last part of the path)
	Import        string         `mapstructure:"import,omitempty"`         // if not specified, this is the path part of the go mods
	GoMod         string         `mapstructure:"gomod,omitempty"`          // a gomod-compatible spec for the module
	Path          string         `mapstructure:"path,omitempty"`           // an optional path to the local version of this module
	SourceArchive *SourceArchive `mapstructure:"source_archive,omitempty"` // an optional remote source archive that is downloaded, verified and used as the module's replace target

	// fromSourceArchive marks modules whose Path was resolved from a SourceArchive.
	// Such paths always remain absolute (they live in a machine-local cache).
	fromSourceArchive bool `mapstructure:"-"`
}

// SourceArchive describes a remote source archive that OCB downloads, verifies,
// extracts, and uses as the module's replace target. This is intended for
// components whose VCS contents do not compile because generated code is not
// committed and is instead published as a release asset.
type SourceArchive struct {
	URL       string `mapstructure:"url,omitempty"`        // the URL of the source archive (https or file scheme)
	SHA256    string `mapstructure:"sha256,omitempty"`     // the expected hex-encoded sha256 digest of the archive
	SHA256URL string `mapstructure:"sha256_url,omitempty"` // a URL to a SHA256SUMS-style file from which to resolve the digest
	Subdir    string `mapstructure:"subdir,omitempty"`     // an optional subdirectory within the archive where the module's go.mod lives
}

type retry struct {
	numRetries int
	wait       time.Duration
}

// NewDefaultConfig creates a new config, with default values
func NewDefaultConfig() (*Config, error) {
	log, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("failed to obtain a logger instance: %v", err))
	}

	outputDir, err := os.MkdirTemp("", "otelcol-distribution")
	if err != nil {
		return nil, err
	}

	return &Config{
		OtelColVersion: DefaultBetaOtelColVersion,
		Logger:         log,
		Distribution: Distribution{
			OutputPath: outputDir,
			Module:     "go.opentelemetry.io/collector/cmd/builder",
		},
		// basic retry if error from go mod command (in case of transient network error).
		// retry 3 times with 5 second spacing interval
		downloadModules: retry{
			numRetries: 3,
			wait:       5 * time.Second,
		},
		ConfmapProviders: []Module{
			{
				GoMod: "go.opentelemetry.io/collector/confmap/provider/envprovider " + DefaultStableOtelColVersion,
			},
			{
				GoMod: "go.opentelemetry.io/collector/confmap/provider/fileprovider " + DefaultStableOtelColVersion,
			},
			{
				GoMod: "go.opentelemetry.io/collector/confmap/provider/httpprovider " + DefaultStableOtelColVersion,
			},
			{
				GoMod: "go.opentelemetry.io/collector/confmap/provider/httpsprovider " + DefaultStableOtelColVersion,
			},
			{
				GoMod: "go.opentelemetry.io/collector/confmap/provider/yamlprovider " + DefaultStableOtelColVersion,
			},
		},
	}, nil
}

// Validate checks whether the current configuration is valid
func (c *Config) Validate() error {
	return multierr.Combine(
		validateModules("extension", c.Extensions),
		validateModules("receiver", c.Receivers),
		validateModules("exporter", c.Exporters),
		validateModules("processor", c.Processors),
		validateModules("connector", c.Connectors),
		validateModules("provider", c.ConfmapProviders),
		validateModules("converter", c.ConfmapConverters),
		validateTelemetry(c),
	)
}

// SetGoPath sets go path
func (c *Config) SetGoPath() error {
	if !c.SkipCompilation || !c.SkipGetModules {
		//nolint:gosec // #nosec G204
		if _, err := exec.Command(c.Distribution.Go, "env").CombinedOutput(); err != nil {
			path, err := exec.LookPath("go")
			if err != nil {
				return ErrGoNotFound
			}
			c.Distribution.Go = path
		}
		c.Logger.Info("Using go", zap.String("go-executable", c.Distribution.Go))
	}
	return nil
}

// ParseModules will parse the Modules entries and populate the missing values
func (c *Config) ParseModules() error {
	// Resolve any declared source archives before path handling, so that the
	// downloaded/extracted location can be used as the module's replace target.
	if err := c.resolveSourceArchives(); err != nil {
		return err
	}

	var err error
	usedNames := make(map[string]int)

	c.Extensions, err = c.parseModules(c.Extensions, usedNames)
	if err != nil {
		return err
	}

	c.Receivers, err = c.parseModules(c.Receivers, usedNames)
	if err != nil {
		return err
	}

	c.Exporters, err = c.parseModules(c.Exporters, usedNames)
	if err != nil {
		return err
	}

	c.Processors, err = c.parseModules(c.Processors, usedNames)
	if err != nil {
		return err
	}

	c.Connectors, err = c.parseModules(c.Connectors, usedNames)
	if err != nil {
		return err
	}

	telemetry, err := c.parseModules([]Module{c.Telemetry}, usedNames)
	if err != nil {
		return err
	}
	c.Telemetry = telemetry[0]

	c.ConfmapProviders, err = c.parseModules(c.ConfmapProviders, usedNames)
	if err != nil {
		return err
	}
	c.ConfmapConverters, err = c.parseModules(c.ConfmapConverters, usedNames)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) allComponents() []Module {
	return slices.Concat(c.Exporters, c.Receivers, c.Processors, c.Extensions, c.Connectors, []Module{c.Telemetry}, c.ConfmapProviders, c.ConfmapConverters)
}

func validateModules(name string, mods []Module) error {
	for i, mod := range mods {
		if mod.GoMod == "" {
			return fmt.Errorf("%s module at index %v: %w", name, i, errMissingGoMod)
		}
		if err := validateSourceArchive(mod); err != nil {
			return fmt.Errorf("%s module at index %v: %w", name, i, err)
		}
	}
	return nil
}

// validateSourceArchive checks the source_archive block of a module, if present.
func validateSourceArchive(mod Module) error {
	if mod.SourceArchive == nil {
		return nil
	}
	sa := mod.SourceArchive
	if mod.Path != "" {
		return errors.New("source_archive and path cannot both be set on the same module")
	}
	if sa.URL == "" {
		return errors.New("source_archive requires url")
	}
	if err := validateArchiveURLScheme("url", sa.URL); err != nil {
		return err
	}

	switch {
	case sa.SHA256 != "" && sa.SHA256URL != "":
		return errors.New("source_archive: exactly one of sha256 or sha256_url must be set, not both")
	case sa.SHA256 == "" && sa.SHA256URL == "":
		return errors.New("source_archive: exactly one of sha256 or sha256_url must be set")
	}

	if sa.SHA256 != "" {
		if len(sa.SHA256) != 64 {
			return fmt.Errorf("source_archive: sha256 must be 64 hex characters, got %d", len(sa.SHA256))
		}
		if _, err := hex.DecodeString(sa.SHA256); err != nil {
			return fmt.Errorf("source_archive: sha256 is not valid hex: %w", err)
		}
	}

	if sa.SHA256URL != "" {
		if err := validateArchiveURLScheme("sha256_url", sa.SHA256URL); err != nil {
			return err
		}
	}

	return nil
}

func validateArchiveURLScheme(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("source_archive: %s is not a valid URL: %w", field, err)
	}
	if u.Scheme != "https" && u.Scheme != "file" {
		return fmt.Errorf("source_archive: %s scheme must be https or file, got %q", field, u.Scheme)
	}
	return nil
}

// validateTelemetry ensures there is a valid telemetry module specified.
// If the field is not set, it is defaulted to otelconftelemetry.
func validateTelemetry(c *Config) error {
	// We cannot set this in createDefaultConfig, since koanf merges maps and we
	// would get a blend of this value and user-provided values. Once
	// otelconftelemetry is its own module (that is, the `Import` field is not
	// set), we can likely move the default to createDefaultConfig.
	if c.Telemetry.Name == "" && c.Telemetry.Import == "" && c.Telemetry.GoMod == "" && c.Telemetry.Path == "" {
		c.Telemetry = Module{
			GoMod:  "go.opentelemetry.io/collector/service " + DefaultBetaOtelColVersion,
			Import: "go.opentelemetry.io/collector/service/telemetry/otelconftelemetry",
		}
	} else if c.Telemetry.GoMod == "" {
		return fmt.Errorf("telemetry module: %w", errMissingGoMod)
	}

	return nil
}

func (c *Config) parseModules(mods []Module, usedNames map[string]int) ([]Module, error) {
	var parsedModules []Module
	for _, mod := range mods {
		if mod.Import == "" {
			mod.Import = strings.Split(mod.GoMod, " ")[0]
		}

		if mod.Name == "" {
			parts := strings.Split(mod.Import, "/")
			mod.Name = parts[len(parts)-1]
		}

		originalModName := mod.Name
		if count, exists := usedNames[mod.Name]; exists {
			var newName string
			for {
				newName = fmt.Sprintf("%s%d", mod.Name, count+1)
				if _, transformedExists := usedNames[newName]; !transformedExists {
					break
				}
				count++
			}
			mod.Name = newName
			usedNames[newName] = 1
		}
		usedNames[originalModName] = 1

		// Check if path is empty, otherwise filepath.Abs replaces it with current path ".".
		if mod.Path != "" {
			var err error
			absPath, err := filepath.Abs(mod.Path)
			if err != nil {
				return mods, fmt.Errorf("failed to resolve absolute path for %s: %w", mod.Path, err)
			}

			if c.Distribution.UseAbsoluteReplacePaths || mod.fromSourceArchive {
				// Archive-derived paths live in a machine-local cache; relative
				// paths across volumes are fragile, so always keep them absolute.
				mod.Path = absPath
			} else {
				absOutputPath, err := filepath.Abs(c.Distribution.OutputPath)
				if err != nil {
					return mods, fmt.Errorf("failed to resolve absolute path for output dir %s: %w", c.Distribution.OutputPath, err)
				}
				mod.Path, err = filepath.Rel(absOutputPath, absPath)
				if err != nil {
					return mods, fmt.Errorf("failed to make path relative to output dir: %w", err)
				}
			}
			mod.Path = filepath.ToSlash(mod.Path)

			// Check if the path exists using the absolute path
			if _, err := os.Stat(absPath); os.IsNotExist(err) {
				return mods, fmt.Errorf("filepath does not exist: %s", absPath)
			}
		}

		parsedModules = append(parsedModules, mod)
	}

	return parsedModules, nil
}

// MarshalYAML encodes Config to YAML using mapstructure tags, omitting zero values.
func (c Config) MarshalYAML() (any, error) {
	return structToMap(c), nil
}

// structToMap converts a struct to a map[string]any using mapstructure tags.
// Fields tagged with mapstructure:"-" are skipped.
// Fields tagged with omitempty are omitted when zero.
func structToMap(v any) map[string]any {
	rv := reflect.ValueOf(v)
	rt := rv.Type()
	result := make(map[string]any)

	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		fv := rv.Field(i)

		if !field.IsExported() {
			continue
		}

		tag := field.Tag.Get("mapstructure")
		if tag == "" {
			continue
		}

		parts := strings.SplitN(tag, ",", 2)
		key := parts[0]
		if key == "-" {
			continue
		}
		omitempty := len(parts) == 2 && parts[1] == "omitempty"

		val := encodeValue(fv)
		if omitempty && isEmpty(val) {
			continue
		}

		result[key] = val
	}

	return result
}

// encodeValue recursively encodes a reflect.Value for use in a YAML map.
// Structs are converted via structToMap, slices are encoded element by element,
// pointers are dereferenced (nil pointers become nil), and all other kinds are
// returned as-is.
func encodeValue(rv reflect.Value) any {
	switch rv.Kind() {
	case reflect.Struct:
		return structToMap(rv.Interface())
	case reflect.Ptr:
		if rv.IsNil() {
			return nil
		}
		return encodeValue(rv.Elem())
	case reflect.Slice:
		if rv.IsNil() {
			return nil
		}
		s := make([]any, rv.Len())
		for i := range rv.Len() {
			s[i] = encodeValue(rv.Index(i))
		}
		return s
	default:
		return rv.Interface()
	}
}

func isEmpty(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	//nolint:exhaustive
	switch rv.Kind() {
	case reflect.Map:
		return rv.Len() == 0
	case reflect.Slice:
		return rv.IsNil() || rv.Len() == 0
	default:
		return rv.IsZero()
	}
}

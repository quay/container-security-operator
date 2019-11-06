package labeller

import (
	"io/ioutil"
	"os"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	Namespaces        []string               `yaml:"namespaces"`
	Interval          time.Duration          `yaml:"interval"`
	SecurityScanner   SecurityScannerOptions `yaml:"securityScanner"`
	LabelPrefix       string                 `yaml:"labelPrefix"`
	PrometheusAddr    string                 `yaml:"prometheusAddr"`
	WellknownEndpoint string                 `yaml:"wellknownEndpoint"`
}

type SecurityScannerOptions struct {
	Host       string `yaml:"host"`
	Token      string `yaml:"token"`
	APIVersion int    `yaml:"apiVersion"`
	Type       string `yaml:"type"`
}

// YAML configuration with all SecurityLabeller configuration under top-level "security-labeller" key
type File struct {
	SecurityLabeller Config `yaml:"securitylabeller"`
}

// Load security labeller config
func LoadConfig(cfgPath string) (*Config, error) {
	var cfgFile File
	var config *Config

	f, err := os.Open(os.ExpandEnv(cfgPath))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	d, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(d, &cfgFile)
	if err != nil {
		return nil, err
	}

	config = &cfgFile.SecurityLabeller

	return config, nil
}

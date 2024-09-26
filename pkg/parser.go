package waf

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

func parseIntoConfig(filePath string) (Config, error) {
	var config Config
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return Config{}, fmt.Errorf("could not read config file at %s: %v", filePath, err)
	}
	if err := yaml.Unmarshal(bytes, &config); err != nil {
		return Config{}, fmt.Errorf("could not parse config file: %v", err)
	}
	return config, nil
}

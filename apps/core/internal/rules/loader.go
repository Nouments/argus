package rules

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadRulesFromFile loads a YAML file containing a sequence of rules.
func LoadRulesFromFile(path string) ([]Rule, error) {
	if path == "" {
		return nil, fmt.Errorf("path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

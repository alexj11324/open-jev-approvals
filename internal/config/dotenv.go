package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func LoadDotEnv(path string) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return fmt.Errorf("invalid .env entry")
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, strings.Trim(strings.TrimSpace(value), "\"'"))
		}
	}
	return scanner.Err()
}

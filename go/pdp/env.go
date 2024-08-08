package zerver

import (
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Wrapper for godotenv.Load that expands ~ to $HOME
func LoadEnv(files ...string) error {
	for _, file := range files {
		// see if file starts with ~ and replace with $HOME
		if strings.HasPrefix(file, "~") {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			file = strings.Replace(file, "~", home, 1)
		}
		if err := godotenv.Load(file); err != nil {
			return err
		}
	}
	return nil
}

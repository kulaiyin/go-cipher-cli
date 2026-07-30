package param

import (
	"fmt"
	"strconv"
)

var ruleRegistry = map[string]func(args []string, flagName string) func(string) error{}

func init() {
	ruleRegistry["min_length"] = func(args []string, flagName string) func(string) error {
		n, _ := strconv.Atoi(args[0])
		return func(v string) error {
			if len(v) < n {
				return fmt.Errorf("--%s must be at least %d characters", flagName, n)
			}
			return nil
		}
	}
	ruleRegistry["has_letter_digit_special"] = func(args []string, flagName string) func(string) error {
		return func(v string) error {
			hasLetter, hasDigit, hasSpecial := false, false, false
			for _, r := range v {
				switch {
				case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
					hasLetter = true
				case r >= '0' && r <= '9':
					hasDigit = true
				default:
					hasSpecial = true
				}
			}
			if !hasLetter || !hasDigit || !hasSpecial {
				return fmt.Errorf("--%s must contain at least one letter, one digit, and one special character", flagName)
			}
			return nil
		}
	}
}

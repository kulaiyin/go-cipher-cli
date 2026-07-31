package param

import (
	"fmt"
	"strconv"

	"go-cipher-cli/internal/i18n"
)

var ruleRegistry = map[string]func(args []string, flagName string, values FieldValues) func(string) error{}

func init() {
	ruleRegistry["min_length"] = func(args []string, flagName string, _ FieldValues) func(string) error {
		n, _ := strconv.Atoi(args[0])
		return func(v string) error {
			if len(v) < n {
				return fmt.Errorf("%s", i18n.TWithData("param.error.min_length", map[string]interface{}{
					"Flag": flagName, "Min": n,
				}))
			}
			return nil
		}
	}
	ruleRegistry["has_letter_digit_special"] = func(args []string, flagName string, _ FieldValues) func(string) error {
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
				return fmt.Errorf("%s", i18n.TWithData("param.error.has_letter_digit_special", map[string]interface{}{
					"Flag": flagName,
				}))
			}
			return nil
		}
	}
	ruleRegistry["int_range"] = func(args []string, flagName string, _ FieldValues) func(string) error {
		min, _ := strconv.Atoi(args[0])
		max, _ := strconv.Atoi(args[1])
		return func(v string) error {
			n, err := strconv.Atoi(v)
			if err != nil || n < min || n > max {
				return fmt.Errorf("%s", i18n.TWithData("param.error.int_range", map[string]interface{}{
					"Flag": flagName, "Min": min, "Max": max,
				}))
			}
			return nil
		}
	}
}

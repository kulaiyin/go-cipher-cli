package cmd

import (
	"go-cipher-cli/internal/param"
)

// fieldEntry binds one declarative parameter field to its flag name and the
// string it reads/writes. Field values live either in Field.Type or Field.Value
// depending on the command; target points at whichever one holds the flag value.
type fieldEntry struct {
	field    *param.Field
	target   *string
	flagName string
}

// valuesFrom derives a snapshot of the current parameter values from field
// entries, keyed by flag name. It is the shared replacement for each command's
// hand-written values() method and always reflects the actual target (so a
// field whose value lives in Type is read correctly).
func valuesFrom(entries []fieldEntry) param.FieldValues {
	vals := make(param.FieldValues, len(entries))
	for _, e := range entries {
		vals[e.flagName] = *e.target
	}
	return vals
}

// validateFields runs each entry's Field.Validate, honoring Visible predicates,
// against the given values snapshot. Shared by all declarative commands.
func validateFields(entries []fieldEntry, vals param.FieldValues) error {
	for _, e := range entries {
		if e.field.Visible != nil && !e.field.Visible(vals) {
			continue
		}
		if err := e.field.Validate(*e.target, e.flagName, vals); err != nil {
			return err
		}
	}
	return nil
}

// promptInteractive prompts for empty interactive fields in declaration order,
// honoring Visible predicates. Values are rebuilt each iteration so a previous
// prompt can change the visibility of later fields (e.g. mode). No-op when
// stdin is not a terminal.
func promptInteractive(entries []fieldEntry) error {
	if !param.IsStdinTerminal() {
		return nil
	}
	for _, e := range entries {
		vals := valuesFrom(entries)
		if e.field.Visible != nil && !e.field.Visible(vals) {
			continue
		}
		if !e.field.Interactive {
			continue
		}
		if *e.target != "" {
			continue
		}
		if err := e.field.Prompt(e.target, e.flagName); err != nil {
			return err
		}
	}
	return nil
}

// paramSet is the declarative parameter lifecycle shared by standard-mode
// commands: normalize + validate, an optional afterStandardize hook, then
// interactive prompting, then the command's execute function. Each command
// declares a paramSet[T] and lets run() drive the flow, keeping only its field
// configuration, its fieldEntries() list, and its run<Cmd> function.
type paramSet[T any] struct {
	// fields returns the command's field entries in validation/prompt order.
	fields func(p *T) []fieldEntry
	// normalize applies command-specific normalization (trimming, case
	// folding) before validation. Optional.
	normalize func(p *T)
	// afterStandardize runs after validation but before prompting, for
	// cross-field defaults that Field declarations cannot express. Optional.
	afterStandardize func(p *T) error
	// execute runs the command body after all params are resolved. Optional
	// (placeholder commands leave it nil).
	execute func(p *T) error
}

// standardize applies normalize, validation, and the afterStandardize hook
// without prompting or executing. Exposed so tests can exercise validation and
// cross-field resolution in isolation.
func (s *paramSet[T]) standardize(p *T) error {
	if s.normalize != nil {
		s.normalize(p)
	}
	if err := validateFields(s.fields(p), valuesFrom(s.fields(p))); err != nil {
		return err
	}
	if s.afterStandardize != nil {
		return s.afterStandardize(p)
	}
	return nil
}

// run drives the full lifecycle: standardize, interactive prompting, then
// execute. This is the RunE body shared by all declarative commands.
func (s *paramSet[T]) run(p *T) error {
	if err := s.standardize(p); err != nil {
		return err
	}
	if err := promptInteractive(s.fields(p)); err != nil {
		return err
	}
	if s.execute != nil {
		return s.execute(p)
	}
	return nil
}

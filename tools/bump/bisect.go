package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// dropped records an atom that was rewound, and why, so the pull request body
// can say what did not move instead of leaving it silently stale.
type dropped struct {
	Name   string
	Reason string
	Log    string
}

// applyAtoms keeps every atom it can. The optimistic path applies the whole set
// at once; only when that fails does it split, so a healthy day costs one gate
// run and a bad day costs log2(n) rather than n.
//
// The split assumes a failure is attributable to one side. A genuine
// interaction between two atoms shows up as both being dropped, which is the
// safe direction to be wrong in.
func applyAtoms(ctx context.Context, r *repo, atoms []atom) ([]string, []dropped, error) {
	if len(atoms) == 0 {
		return nil, nil, nil
	}

	base, err := saveModState(r)
	if err != nil {
		return nil, nil, err
	}

	summaries, applyErr := applySet(ctx, r, atoms)
	if applyErr == nil {
		return summaries, nil, nil
	}

	err = base.restore(r)
	if err != nil {
		return nil, nil, err
	}

	if len(atoms) == 1 {
		return nil, []dropped{{
			Name:   atoms[0].Name,
			Reason: reasonOf(applyErr),
			Log:    logOf(applyErr),
		}}, nil
	}

	mid := len(atoms) / 2

	keptFirst, dropFirst, err := applyAtoms(ctx, r, atoms[:mid])
	if err != nil {
		return nil, nil, err
	}

	keptSecond, dropSecond, err := applyAtoms(ctx, r, atoms[mid:])
	if err != nil {
		return nil, nil, err
	}

	return append(keptFirst, keptSecond...), append(dropFirst, dropSecond...), nil
}

// applySet applies every atom, settles go.mod and asks the atom gate whether
// the result is viable.
func applySet(ctx context.Context, r *repo, atoms []atom) ([]string, error) {
	summaries := make([]string, 0, len(atoms))

	for _, a := range atoms {
		summary, err := a.Apply(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.Name, err)
		}

		summaries = append(summaries, summary)
	}

	err := settle(ctx, r)
	if err != nil {
		return nil, err
	}

	err = atomGate(ctx, r)
	if err != nil {
		return nil, err
	}

	return summaries, nil
}

// reasonOf renders a one-line cause for the report.
func reasonOf(err error) string {
	if ce, ok := errors.AsType[*cmdError](err); ok {
		return fmt.Sprintf("`%s` failed", strings.Join(ce.Argv, " "))
	}

	return strings.SplitN(err.Error(), "\n", 2)[0]
}

// logOf returns the captured output of a failing command, if there was one.
func logOf(err error) string {
	if ce, ok := errors.AsType[*cmdError](err); ok {
		return ce.Tail
	}

	return ""
}

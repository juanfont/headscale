package main

import (
	"context"
	"log"
)

type state string

const (
	stateApplied state = "applied"
	statePartial state = "partial"
	stateEmpty   state = "unchanged"
	stateDropped state = "dropped"
	stateSkipped state = "skipped"
)

// change is what an area did, in a shape the report can render directly.
type change struct {
	Summary string
	Detail  []string
	// Drops are sub-units the area rewound on its own, such as a single
	// dependency that failed to build.
	Drops []dropped
	Empty bool
}

// area is one independently revertible unit of work. Areas are the granularity
// at which the bot succeeds or fails: each becomes its own commit, so a broken
// one can be dropped without disturbing the others.
type area struct {
	Name  string
	Needs []string
	// Message renders the commit subject, in the repository's
	// "package: imperative description" style.
	Message func(change) string
	Apply   func(ctx context.Context, r *repo) (change, error)
	// Gate is a cheap structural check. Anything that needs a build belongs
	// in the final gate instead.
	Gate func(ctx context.Context, r *repo) error
}

type result struct {
	Area   string
	State  state
	Change change
	Reason string
	Log    string
	Commit string
}

// allAreas is the running order. Regeneration comes last because it consumes
// what everything before it settled: the toolchain from the lock, the module
// versions, and the generator pin from the Makefile.
func allAreas() []area {
	areas := []area{
		{
			Name:    "flake",
			Apply:   applyFlake,
			Gate:    gateFlake,
			Message: func(c change) string { return "flake.lock: update " + c.Summary },
		},
	}

	areas = append(areas, toolAreas()...)
	areas = append(areas,
		area{
			Name:    "gomod",
			Needs:   []string{"flake"},
			Apply:   applyGoMod,
			Gate:    gateGoMod,
			Message: func(c change) string { return "go.mod: " + c.Summary },
		},
		area{
			Name:    "docker-go",
			Needs:   []string{"flake"},
			Apply:   applyDockerGo,
			Gate:    gateDockerGo,
			Message: func(c change) string { return "Dockerfile: bump " + c.Summary },
		},
	)
	areas = append(areas, imageAreas()...)

	return append(areas, area{
		Name:    "generate",
		Needs:   []string{"gomod"},
		Apply:   applyGenerate,
		Gate:    gateGenerate,
		Message: func(change) string { return "all: regenerate generated files" },
	})
}

// runAreas applies each area in order, committing the ones that hold and
// rewinding the ones that do not. A dropped area leaves no residue because the
// rewind is a hard reset to a commit that is known good.
func runAreas(ctx context.Context, r *repo, areas []area, want func(string) bool) ([]result, error) {
	states := make(map[string]state, len(areas))
	results := make([]result, 0, len(areas))

	record := func(res result) {
		states[res.Area] = res.State
		results = append(results, res)
	}

	for _, a := range areas {
		if !want(a.Name) {
			record(result{Area: a.Name, State: stateSkipped, Reason: "not selected"})

			continue
		}

		if blocker, ok := blockedBy(a, states); ok {
			record(result{Area: a.Name, State: stateSkipped, Reason: "depends on dropped " + blocker})

			continue
		}

		res, err := runArea(ctx, r, a)
		if err != nil {
			return results, err
		}

		record(res)
	}

	return results, nil
}

// blockedBy reports the first dependency that did not survive.
func blockedBy(a area, states map[string]state) (string, bool) {
	for _, need := range a.Needs {
		if states[need] == stateDropped {
			return need, true
		}
	}

	return "", false
}

func runArea(ctx context.Context, r *repo, a area) (result, error) {
	snapshot, err := headSHA(ctx, r)
	if err != nil {
		return result{}, err
	}

	log.Printf("area %s: applying", a.Name)

	rewind := func(res result) (result, error) {
		err := resetTo(ctx, r, snapshot)
		if err != nil {
			return result{}, err
		}

		return res, nil
	}

	ch, err := a.Apply(ctx, r)
	if err != nil {
		return rewind(result{
			Area: a.Name, State: stateDropped,
			Reason: reasonOf(err), Log: logOf(err),
		})
	}

	if ch.Empty {
		return rewind(result{Area: a.Name, State: stateEmpty, Change: ch})
	}

	if a.Gate != nil {
		err := a.Gate(ctx, r)
		if err != nil {
			return rewind(result{
				Area: a.Name, State: stateDropped, Change: ch,
				Reason: reasonOf(err), Log: logOf(err),
			})
		}
	}

	err = commitAll(ctx, r, a.Message(ch))
	if err != nil {
		return result{}, err
	}

	sha, err := headSHA(ctx, r)
	if err != nil {
		return result{}, err
	}

	st := stateApplied
	if len(ch.Drops) > 0 {
		st = statePartial
	}

	return result{Area: a.Name, State: st, Change: ch, Commit: sha}, nil
}

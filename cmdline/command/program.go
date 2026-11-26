package command

import (
	"context"
	"encoding/json"
	"reflect"
)

// Program is what a program built on this package gives the builder: its
// name, the session its commands call a server with (S, as Ctx.API), and
// how it reads that server's errors and objects. The builder
// does the rest, the same for every program.
type Program[S any] struct {
	// Name is the program as a command line starts with it; Short is the
	// first line of the root help.
	Name, Short string
	// Version is the line --version prints in the run of ctx, Env.Context;
	// a program with none has no --version.
	Version func(ctx context.Context) string

	// Session is the Ctx.API of a run; server says that the line talks to
	// a server, and is false for a Local command, which calls none.
	Session func(c Ctx[S], server bool) (S, error)
	// Error is err, an error of a call made with the session, as the
	// program says it. It is applied to what Run, Confirm and a read of a
	// target return, before the builder reads the error.
	Error func(s S, err error) error
	// Sentence is the text of an error a run ends with; nil is its Error.
	Sentence func(err error) string
	// Answer is the body the server sent that v, a result, was read from,
	// for -o json, which prints an answer as it came.
	Answer func(s S, v any) (json.RawMessage, bool)
	// Target names the server of a run in a sentence: "the server at
	// <Target>".
	Target func(s S) string

	// Entities are the types of target a lookup finds.
	Entities []Entity

	// Aliases are the aliases a command may have.
	Aliases []string
	// ConfigEnv is the variable that names the config file, as --config
	// does.
	ConfigEnv string
	// Server is what the root help says a server command talks to: "a
	// running headscale".
	Server string
}

// program is a Program with its session erased, as the tree keeps it.
type program struct {
	Program[any]

	session func(r *run, ctx context.Context, server bool) (any, error)
	// sessionType is S, which every spec of the program is made for.
	sessionType reflect.Type
}

// erase is p as the tree keeps it.
func erase[S any](p Program[S]) program {
	e := program{
		Name: p.Name, Short: p.Short, Version: p.Version,
		Sentence: p.Sentence, Entities: p.Entities,
		Aliases: p.Aliases, ConfigEnv: p.ConfigEnv, Server: p.Server,
		sessionType: reflect.TypeFor[S](),
	}

	api := func(s any) S { v, _ := s.(S); return v }

	e.Error = func(s any, err error) error {
		if p.Error == nil || err == nil {
			return err
		}

		return p.Error(api(s), err)
	}

	e.Answer = func(s any, v any) (json.RawMessage, bool) {
		if p.Answer == nil {
			return nil, false
		}

		return p.Answer(api(s), v)
	}

	e.Target = func(s any) string {
		if p.Target == nil {
			return ""
		}

		return p.Target(api(s))
	}

	e.session = func(r *run, ctx context.Context, server bool) (any, error) {
		// A program with no session gives its commands the zero S.
		if p.Session == nil {
			var none S

			return none, nil
		}

		return p.Session(Ctx[S]{Context: ctx, run: r}, server)
	}

	return e
}

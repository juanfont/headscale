package command

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/juanfont/headscale/cmdline"
)

// Program is what a program built on this package gives the builder: its
// name, the session its commands call a server with (S, as Ctx.API), and
// how it reads that server's errors, credentials and objects. The builder
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

	// Refusal is the code of err when it is a refusal of the server; "" for
	// any other error. Precondition is the code that refuses an If-Match.
	Refusal      func(err error) string
	Precondition string
	// Again marks err, the refusal of a guard on the second try: the
	// target changed again.
	Again func(err error)
	// About gives err, a refusal, what the command knows of it: the
	// target as the command read it, the word it was typed as, and the
	// expiry it sent, zero when none.
	About func(err error, target Object, word string, expiry time.Time)
	// Fields names, in err, the flags and arguments of the input type in
	// that filled the fields of the body the server refused.
	Fields func(err error, in reflect.Type) error
	// MayBeMade reports whether err leaves a change unknown: a write sent
	// and not answered, or answered with what cannot be read.
	MayBeMade func(err error) bool

	// Entities are the types of target a lookup finds, and Readers the
	// other values read once the line is right, such as an owner.
	Entities []Entity
	Readers  []cmdline.Option
	// Owner is the ID of the user word names, for a filter owner=<user>.
	Owner func(ctx context.Context, word string) (string, error)

	// Credentials is the rule at the edge (credential.go).
	Credentials Credentials
	// OpenFields are the fields that hold an interface and no secret, by
	// the struct that has them; Unprintable the types that no result or
	// row may hold, with why (secret.go).
	OpenFields  map[reflect.Type]string
	Unprintable map[reflect.Type]error

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
		Sentence: p.Sentence,
		Refusal:  p.Refusal, Precondition: p.Precondition, Again: p.Again,
		About: p.About, Fields: p.Fields, MayBeMade: p.MayBeMade,
		Entities: p.Entities, Readers: p.Readers, Owner: p.Owner,
		Credentials: p.Credentials, OpenFields: p.OpenFields,
		Unprintable: p.Unprintable, Aliases: p.Aliases, ConfigEnv: p.ConfigEnv,
		Server:      p.Server,
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

// Object is the target of a command as a sentence names it.
type Object struct{ Kind, ID, Name string }

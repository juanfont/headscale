package apiv0

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// hujsonContentType is the policy file itself as a body.
const hujsonContentType = "application/hujson"

// maxPolicyBytes is the largest policy a write takes, as /api/v1 and
// /api/v2 do.
const maxPolicyBytes = 1 << 20

var errNotUTF8 = errors.New("the body is not UTF-8")

// hujsonBodyFormat reads a policy file sent as the body as {"policy": file},
// so both forms of PUT /policy get the same checks.
var hujsonBodyFormat = huma.Format{
	// Never chosen for an answer (hujsonNotAnswered); JSON, should it be.
	Marshal: huma.DefaultJSONFormat.Marshal,
	Unmarshal: func(data []byte, v any) error {
		// encoding/json would put U+FFFD in place of a byte that is not
		// UTF-8, and store a policy that was never sent.
		if !utf8.Valid(data) {
			return errNotUTF8
		}

		wrapped, err := json.Marshal(map[string]string{"policy": string(data)})
		if err != nil {
			return err
		}

		return bodyFormat.Unmarshal(wrapped, v)
	},
}

// Policy is the policy in force.
type Policy struct {
	Policy  string     `doc:"The policy as it is stored or read from the file: HuJSON, with its comments. \"\" when there is none."                               json:"policy"`
	Updated *time.Time `doc:"When the database stored it; null in file mode and when nothing is stored."                                                          json:"updated"       nullable:"true"`
	Mode    string     `doc:"database, or file when the server reads the policy from a file. A file the server refused is not in force; GET /health warns of it." enum:"database,file" json:"mode"`
	Path    string     `doc:"The policy file in file mode, else \"\"."                                                                                            json:"path"`
}

// SetPolicyBody is the policy to write.
type SetPolicyBody struct {
	Policy string `doc:"The policy, HuJSON. With Content-Type application/hujson the body is the policy file itself." json:"policy"`
}

// PolicyError is one problem of a refused policy, in details.policyErrors
// of policy_invalid.
type PolicyError struct {
	Message string `doc:"The problem, a sentence for a person."                                                 json:"message"`
	Line    *int   `doc:"Where the policy text has it, from 1; null when the problem has no place in the text." json:"line"    nullable:"true"`
	Column  *int   `doc:"The column of line, from 1, in bytes; null with line."                                 json:"column"  nullable:"true"`
}

// FailedTest is one assertion of the policy's tests that did not hold, in
// details.failedTests of policy_invalid.
type FailedTest struct {
	Kind   string  `doc:"acl for an entry of tests, ssh for one of sshTests."                       enum:"acl,ssh"           json:"kind"`
	Index  int     `doc:"The position of the test in its list, from 0."                             json:"index"`
	Src    string  `doc:"The source of the test, as written."                                       json:"src"`
	Dst    string  `doc:"The destination that failed, as written."                                  json:"dst"`
	User   *string `doc:"The login user of an ssh test; null for acl."                              json:"user"              nullable:"true"`
	Want   string  `doc:"What the test asserts."                                                    enum:"accept,deny,check" json:"want"`
	Got    string  `doc:"What the policy does."                                                     enum:"accept,deny,check" json:"got"`
	Line   *int    `doc:"Where the policy text has the test, from 1; null when it cannot be found." json:"line"              nullable:"true"`
	Column *int    `doc:"The column of line, from 1, in bytes; null with line."                     json:"column"            nullable:"true"`
}

// PolicyInvalidDetails is details of policy_invalid. Problem.details is one
// free map for every code, so each operation that answers policy_invalid
// names this schema under x-problem-details.
type PolicyInvalidDetails struct {
	PolicyErrors     []PolicyError `doc:"One entry per problem, at most 100."                                                                              json:"policyErrors"     nullable:"false"`
	PolicyErrorCount int           `doc:"How many problems there are in all."                                                                              json:"policyErrorCount"`
	FailedTests      []FailedTest  `doc:"One entry per assertion that did not hold, at most 100."                                                          json:"failedTests"      nullable:"false"`
	FailedTestCount  int           `doc:"How many assertions failed in all."                                                                               json:"failedTestCount"`
	TestsNotRun      int           `doc:"How many entries of tests and sshTests were not run because the policy was refused before them; 0 when they ran." json:"testsNotRun"`
}

type (
	setPolicyInput struct {
		DryRun  bool   `doc:"Run every check of the write, answer what it would answer, and store nothing. Works in file mode too."                                             query:"dryRun"`
		IfMatch string `doc:"The ETag of GET /policy. The write is refused with precondition_failed when the policy changed since; leave it out to write whatever is in force." header:"If-Match"`
		Body    SetPolicyBody
	}

	policyOutput struct {
		ETag string `doc:"A strong hash of the whole answer, quoted, to send back in If-Match on PUT /policy." header:"ETag"`
		Body Policy
	}

	setPolicyOutput struct {
		ETag string `doc:"A strong hash of the whole answer, quoted, to send back in If-Match. A dry run sends none." header:"ETag"`
		Body Policy
	}
)

func registerPolicy(api huma.API, b Backend) {
	tags := []string{"Policy"}

	register(api, huma.Operation{
		OperationID: "getPolicy",
		Method:      http.MethodGet,
		Path:        Prefix + "/policy",
		Summary:     "Read the policy in force",
		Description: "The ETag covers the whole answer; send it back in If-Match on PUT /policy.",
		Tags:        tags,
	}, needs(scope.PolicyFileRead), nil, func(context.Context, *struct{}) (*policyOutput, error) {
		return policyAnswer(b.State.Policy()), nil
	})

	op := huma.Operation{
		OperationID: "setPolicy",
		Method:      http.MethodPut,
		Path:        Prefix + "/policy",
		Summary:     "Replace the policy, or with dryRun=true only check it",
		Description: "The server parses the policy, checks it against its users and nodes, and runs its tests; a failure is policy_invalid with every problem and every failed test. " +
			"The body is {\"policy\": \"…\"}, or the policy file itself with Content-Type application/hujson. " +
			"An empty body is checked as the empty policy in both forms. The body holds at most 1 MiB (too_large); the JSON form holds less policy than the file itself, by its escapes. " +
			"In file mode the write is policy_read_only; a dry run still checks. A dry run answers what the write would, with updated null, as nothing was stored, and no ETag.",
		Tags:         tags,
		MaxBodyBytes: maxPolicyBytes,
	}

	register(api, op, needs(scope.PolicyFile), []answer{
		{code: CodePolicyInvalid},
		{code: CodePolicyReadOnly},
		onError(state.ErrPolicyPrecondition, CodePreconditionFailed, "The policy changed since its ETag was read; nothing was written. Read it again."),
	}, func(_ context.Context, in *setPolicyInput) (*setPolicyOutput, error) {
		tag, ok := revisionFromIfMatch(in.IfMatch)
		if !ok {
			p := newProblem(CodeInvalidField, "A header is not valid.")
			p.Errors = []FieldError{{Location: "header.If-Match", Message: "is not one entity tag, such as \"<etag>\", or *"}}

			return nil, p
		}

		doc := b.State.Policy()
		if doc.Mode != types.PolicyModeDB && !in.DryRun {
			detail := "The policy is read from " + doc.Path + ". Edit that file."
			if doc.Path == "" {
				detail = "No policy file is set (policy.path), and the policy cannot be written while policy.mode is file."
			}

			p := newProblem(CodePolicyReadOnly, detail)
			p.Details["path"] = doc.Path

			return nil, p
		}

		// Compared by the state under the lock of every policy write; a
		// weak tag never matches.
		var match func(state.PolicyDocument) bool
		if tag != "" {
			match = func(d state.PolicyDocument) bool { return `"`+tag+`"` == policyETag(policyBody(d)) }
		}

		pol := []byte(in.Body.Policy)

		if in.DryRun {
			err := b.State.CheckPolicyIf(pol, match)
			if err != nil {
				return nil, policyInvalid(err, "The policy is not valid. Nothing was changed.")
			}

			return &setPolicyOutput{Body: Policy{Policy: in.Body.Policy, Mode: string(doc.Mode), Path: doc.Path}}, nil
		}

		stored, changes, err := b.State.UpdatePolicyTextIf(pol, match) //nolint:contextcheck // the policy store has a deadline of its own, under the policy lock
		b.Change(changes...)

		if err != nil {
			return nil, policyInvalid(err, "The policy is not valid. The policy in force stays.")
		}

		answer := policyAnswer(state.PolicyDocument{Data: stored.Data, Updated: &stored.UpdatedAt, Mode: types.PolicyModeDB})

		return &setPolicyOutput{ETag: answer.ETag, Body: answer.Body}, nil
	})

	problemDetails(api, op.Path, http.MethodPut)

	// The policy file is a body of its own media type. An empty body is the
	// empty policy, refused as it is in the JSON form.
	put := api.OpenAPI().Paths[op.Path].Put
	put.RequestBody.Required = false
	put.RequestBody.Content[hujsonContentType] = &huma.MediaType{Schema: &huma.Schema{
		Type: huma.TypeString, Description: "The policy file, HuJSON.",
	}}

	register(api, huma.Operation{
		OperationID: "reloadPolicy",
		Method:      http.MethodPost,
		Path:        Prefix + "/policy/reload",
		Summary:     "Read the policy again from where it is kept, and install it",
		Description: "Reads the policy file in file mode, the database otherwise. A policy the server refuses is policy_invalid, and the policy in force stays; in file mode GET /health warns of it until a valid file is in force.",
		Tags:        tags,
	}, needs(scope.PolicyFile), []answer{{code: CodePolicyInvalid}}, func(context.Context, *struct{}) (*policyOutput, error) {
		changes, err := b.State.ReloadPolicy() //nolint:contextcheck // the policy store has a deadline of its own, under the policy lock
		b.Change(changes...)

		if err != nil {
			return nil, policyInvalid(err, "The policy is not valid. The old policy is still in force.")
		}

		return policyAnswer(b.State.Policy()), nil
	})

	problemDetails(api, Prefix+"/policy/reload", http.MethodPost)
}

// problemDetails names the schema of details of policy_invalid on an
// operation, under x-problem-details, which also keeps the schema in the
// document.
func problemDetails(api huma.API, path, method string) {
	schema := api.OpenAPI().Components.Schemas.Schema(reflect.TypeFor[PolicyInvalidDetails](), true, "")

	op := api.OpenAPI().Paths[path].Put
	if method == http.MethodPost {
		op = api.OpenAPI().Paths[path].Post
	}

	op.Extensions["x-problem-details"] = map[string]any{string(CodePolicyInvalid): schema}
}

// policyBody is the answer of d.
func policyBody(d state.PolicyDocument) Policy {
	p := Policy{Policy: d.Data, Mode: string(d.Mode), Path: d.Path}
	if d.Updated != nil {
		p.Updated = new(micro(*d.Updated))
	}

	return p
}

// policyAnswer is d with its ETag.
func policyAnswer(d state.PolicyDocument) *policyOutput {
	body := policyBody(d)

	return &policyOutput{ETag: policyETag(body), Body: body}
}

// policyETag is a strong hash of the whole answer, quoted, so it changes
// when the text, the time, the mode or the path does, as RFC 9110 asks.
func policyETag(p Policy) string {
	b, _ := json.Marshal(p) //nolint:errchkjson // strings and a time
	sum := sha256.Sum256(b)

	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// policyInvalid is the policy_invalid problem of a refused policy, with each
// problem and each failed test as data; any other error passes.
func policyInvalid(err error, detail string) error {
	invalid, ok := errors.AsType[*state.InvalidPolicyError](err)
	if !ok {
		return err
	}

	ex := policyv2.Explain(invalid.Policy, invalid.Err)
	if errors.Is(err, state.ErrPolicyFileUnreadable) {
		ex.Errors, ex.ErrorCount = []policyv2.PolicyError{{Message: unreadable(err)}}, 1
	}

	p := newProblem(CodePolicyInvalid, detail)

	place := func(line, column int) (*int, *int) {
		if line > 0 {
			return new(line), new(column)
		}

		return nil, nil
	}

	entries := make([]PolicyError, len(ex.Errors))
	for i, e := range ex.Errors {
		entries[i] = PolicyError{Message: e.Message}
		entries[i].Line, entries[i].Column = place(e.Line, e.Column)
	}

	tests := make([]FailedTest, len(ex.FailedTests))
	for i, f := range ex.FailedTests {
		tests[i] = FailedTest{Kind: f.Kind, Index: f.Index, Src: f.Src, Dst: f.Dst, Want: f.Want, Got: f.Got}
		tests[i].Line, tests[i].Column = place(f.Line, f.Column)

		if f.Kind == "ssh" {
			tests[i].User = new(f.User)
		}
	}

	p.Details = map[string]any{
		"policyErrors":     entries,
		"policyErrorCount": ex.ErrorCount,
		"failedTests":      tests,
		"failedTestCount":  ex.FailedTestCount,
		"testsNotRun":      ex.TestsNotRun,
	}

	return p
}

// unreadable says why the policy file cannot be read, in words of ours: the
// error of the system names paths and calls.
func unreadable(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "the policy file does not exist"
	case errors.Is(err, fs.ErrPermission):
		return "the server may not read the policy file"
	default:
		log.Error().Err(err).Msg("api v0: reading the policy file")

		return "the policy file cannot be read; the server log says why"
	}
}

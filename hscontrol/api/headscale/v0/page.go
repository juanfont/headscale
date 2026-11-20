package apiv0

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PageQuery is the paging of every list. A list's input embeds it, and
// register then declares invalid_page_token; the guard fails a list
// operation without it. A query parameter that is empty or given twice is
// refused before any handler runs; see [requestChecks].
type PageQuery struct {
	PageSize  int    `default:"25"                                                                                               doc:"Rows on one page." maximum:"1000" minimum:"1" query:"pageSize"`
	PageToken string `doc:"nextPageToken of the page before, unchanged, with the same filters. Leave it out for the first page." query:"pageToken"`
}

// pageTokenVersion is the format of a token; a token of another format is
// refused, so the client starts again.
const pageTokenVersion = 1

// maxPageToken bounds the text decoded; the tokens the server makes are far
// shorter.
const maxPageToken = 512

// pageKey signs page tokens. It is made when the process starts: there is
// no default and no setting, and a restart refuses every older token.
var pageKey = func() []byte {
	k := make([]byte, sha256.Size)
	_, _ = rand.Read(k) // never fails, see crypto/rand.Read

	return k
}()

// pageToken is what a token holds. It is signed, so a client can neither
// read meaning into it nor change it.
type pageToken struct {
	Version int    `json:"v"`
	List    string `json:"l"`
	After   string `json:"a"`
	Filters string `json:"f"`
}

// walkKey is the type of the key a list walks by: an ID, or a name such as
// a tag's, compared byte by byte.
type walkKey interface{ uint64 | string }

// page is one page of a list walked by a key: the rows after the key after,
// at most size of them.
type page[K walkKey] struct {
	list    string
	filters string
	size    int
	// started is false on the first page, where after means nothing.
	started bool
	after   K
}

// openPage reads the page asked for of the list named list. filters are the
// values of every filter of the list, in a fixed order, so a token works
// only with the filters it was made for. The error is an invalid_page_token
// problem.
func openPage[K walkKey](q PageQuery, list string, filters ...string) (page[K], error) {
	pg := page[K]{list: list, filters: filterHash(filters), size: q.PageSize}
	if q.PageToken == "" {
		return pg, nil
	}

	tok, ok := openPageToken(q.PageToken)
	if !ok || tok.Version != pageTokenVersion || tok.List != pg.list || tok.Filters != pg.filters {
		return page[K]{}, invalidPageToken()
	}

	switch after := any(&pg.after).(type) {
	case *uint64:
		id, err := strconv.ParseUint(tok.After, 10, 64)
		if err != nil {
			return page[K]{}, invalidPageToken()
		}

		*after = id
	case *string:
		*after = tok.After
	}

	pg.started = true

	return pg, nil
}

// limit is the number of rows to read: one more than the page shows, to
// learn whether more follow.
func (pg page[K]) limit() int { return pg.size + 1 }

// cutPage returns the rows of pg from rows, which are in key order, and the
// token of the next page, "" when none can follow. Rows at or before the
// page's start are skipped, so a list in memory can pass all of its rows.
func cutPage[T any, K walkKey](pg page[K], rows []T, key func(T) K) ([]T, string) {
	start := 0
	for pg.started && start < len(rows) && key(rows[start]) <= pg.after {
		start++
	}

	rows = rows[start:]
	if len(rows) <= pg.size {
		return rows, ""
	}

	rows = rows[:pg.size]

	return rows, sealPageToken(pageToken{
		Version: pageTokenVersion,
		List:    pg.list,
		After:   fmt.Sprint(key(rows[len(rows)-1])),
		Filters: pg.filters,
	})
}

// filterHash binds a token to the filters: each value is length-prefixed,
// so no two lists of values give the same input.
func filterHash(filters []string) string {
	h := sha256.New()
	for _, f := range filters {
		_ = binary.Write(h, binary.BigEndian, uint64(len(f)))
		h.Write([]byte(f))
	}

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}

func sealPageToken(t pageToken) string {
	payload, _ := json.Marshal(t) //nolint:errchkjson // strings and an int

	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(pageMAC(payload))
}

// openPageToken checks the signature before it reads anything, and reads
// strictly: an unknown member or a member of the wrong type fails.
func openPageToken(s string) (pageToken, bool) {
	if len(s) > maxPageToken {
		return pageToken{}, false
	}

	enc, sig, ok := strings.Cut(s, ".")
	if !ok {
		return pageToken{}, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return pageToken{}, false
	}

	mac, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(mac, pageMAC(payload)) {
		return pageToken{}, false
	}

	var t pageToken

	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()

	if dec.Decode(&t) != nil || dec.More() {
		return pageToken{}, false
	}

	return t, true
}

func pageMAC(payload []byte) []byte {
	m := hmac.New(sha256.New, pageKey)
	m.Write(payload)

	return m.Sum(nil)
}

func invalidPageToken() *Problem {
	return newProblem(CodeInvalidPageToken, "The page token is not one this server made for this list and these filters; start again from the first page.")
}

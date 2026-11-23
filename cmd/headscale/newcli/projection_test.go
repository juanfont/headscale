package newcli

import (
	"cmp"
	"encoding/json"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Signed columns edit the default display. A plain selection specifies its complete order.
func TestRapidNodeColumnProjection(t *testing.T) {
	f := newFixture(t, true)
	fleet(t, f)

	run := func(value string) result {
		args := "nodes list"
		if value != "" {
			args += " --columns=" + value
		}

		return f.run(t, cliCase{args: args, pageSize: 10})
	}
	defaults := []string{"id", "name", "owner", "ip", "version", "online", "last-seen", "expiry"}
	optional := []string{"hostname", "os", "ephemeral", "update-available", "register-method", "public-ip", "auth-key", "machine-key", "node-key", "disco-key"}
	base := run("")

	var page struct{ Nodes []map[string]any }
	if base.code != 0 || len(base.answers[nodesPath]) != 1 || json.Unmarshal(base.answers[nodesPath][0], &page) != nil || len(page.Nodes) == 0 {
		t.Fatalf("node page control: exit=%d pages=%d stderr=%q", base.code, len(base.answers[nodesPath]), base.stderr)
	}

	rows := make([]map[string]string, 0, len(page.Nodes))
	for _, node := range page.Nodes {
		rows = append(rows, nodeProjectionValues(t, node))
	}
	// For formatted fields, one-column output supplies the boundaries without guessing where a cell ends.
	for _, name := range []string{"owner", "last-seen", "expiry"} {
		single := run(name)

		lines := strings.Split(strings.TrimSuffix(single.stdout, "\n"), "\n")
		if single.code != 0 || single.stderr != "" || len(lines) != len(rows)+1 {
			t.Fatalf("single-column control %s: exit=%d rows=%d", name, single.code, len(lines)-1)
		}

		for i, row := range rows {
			row[name] = lines[i+1]
		}
	}

	gap := regexp.MustCompile(` {2,}`)

	var hidden, addedColumns, removedColumns, noChange int

	checkHostnameProjection(t, run, base)

	all := slices.Concat(defaults, optional)
	edit := rapid.Custom(func(rt *rapid.T) string {
		name := rapid.SampledFrom(all).Draw(rt, "name")
		if rapid.Bool().Draw(rt, "add") {
			return "+" + name
		}

		return "-" + name
	})
	edits := rapid.SliceOfNDistinct(edit, 1, len(all), func(word string) string { return word[1:] })

	rapid.Check(t, func(rt *rapid.T) {
		removed := map[string]bool{}

		var added []string

		words := edits.Draw(rt, "column edits")
		for _, word := range words {
			name := word[1:]
			if word[0] == '-' {
				removed[name] = true
			} else if !slices.Contains(defaults, name) {
				added = append(added, name)
			}
		}

		want := slices.Concat(slices.DeleteFunc(slices.Clone(defaults), func(name string) bool { return removed[name] }), added)

		got := run(strings.Join(words, ","))
		if got.code != 0 || got.stderr != "" {
			rt.Fatalf("edit %v: exit=%d stderr=%q", words, got.code, got.stderr)
		}

		if len(want) == 0 {
			if strings.TrimSpace(got.stdout) != "" {
				rt.Fatalf("edit %v: removed all columns, got %q", words, got.stdout)
			}

			return
		}

		checkProjectedCells(rt, words, want, got.stdout, gap, rows)

		if len(added) != 0 {
			addedColumns++
		}

		if len(want)-len(added) < len(defaults) {
			removedColumns++
		}

		if slices.Equal(want, defaults) {
			noChange++
		}

		if !slices.Contains(want, "hostname") {
			hidden++
		}

		explicit := run(strings.Join(want, ","))
		if explicit.code != 0 || explicit.stderr != "" || got.stdout != explicit.stdout {
			rt.Fatalf("edit %v versus explicit %v: got %q, want %q, diagnostic %q", words, want, got.stdout, explicit.stdout, explicit.stderr)
		}
	})
	t.Logf("model classes added-columns=%d removed-columns=%d unchanged-defaults=%d hidden-hostname=%d", addedColumns, removedColumns, noChange, hidden)
}

func checkHostnameProjection(t *testing.T, run func(string) result, base result) {
	t.Helper()

	for _, value := range []string{"-hostname", "+hostname", "hostname", "id,-hostname"} {
		got := run(value)
		switch value {
		case "-hostname":
			if got.code != 0 || got.stderr != "" || got.stdout != base.stdout || strings.Contains(got.stdout, "HOSTNAME") {
				t.Fatalf("%s changed the default table: %+v", value, got.stdout)
			}
		case "+hostname":
			header, _, _ := strings.Cut(got.stdout, "\n")
			if got.code != 0 || got.stderr != "" || !strings.HasSuffix(header, "  HOSTNAME") || !strings.Contains(got.stdout, "ubuntu-vm") {
				t.Fatalf("%s missing hostname: %q", value, got.stdout)
			}
		case "hostname":
			if got.code != 0 || got.stderr != "" || got.stdout != "HOSTNAME\nubuntu-vm\nbuilder\ngateway\nubuntu\nweb\n" {
				t.Fatalf("%s: %q", value, got.stdout)
			}
		default:
			if got.code != 1 || got.stdout != "" || !strings.Contains(got.stderr, "plain list") || len(got.asked) != 0 {
				t.Fatalf("%s: exit=%d stdout=%q stderr=%q calls=%q", value, got.code, got.stdout, got.stderr, got.asked)
			}
		}

		t.Logf("%s exit=%d stdout=%q stderr=%q", value, got.code, got.stdout, got.stderr)
	}
}

func nodeProjectionValues(t *testing.T, node map[string]any) map[string]string {
	t.Helper()

	fields := map[string]string{
		"id": "id", "name": "name", "hostname": "hostname", "os": "os", "version": "clientVersion",
		"online": "connectedToControl", "ephemeral": "isEphemeral", "update-available": "updateAvailable",
		"register-method": "registerMethod", "auth-key": "authKeyId", "machine-key": "machineKey", "node-key": "nodeKey", "disco-key": "discoKey",
	}

	cells := make(map[string]string, len(fields)+1)
	for column, key := range fields {
		value, present := node[key]
		if !present {
			t.Fatalf("API node missing %q", key)
		}

		switch v := value.(type) {
		case nil:
			cells[column] = "-"
		case bool:
			cells[column] = "no"
			if v {
				cells[column] = "yes"
			}
		case string:
			cells[column] = cmp.Or(v, "-")
		default:
			t.Fatalf("API node field %s has type %T", key, value)
		}
	}

	addresses, ok := node["addresses"].([]any)
	if !ok {
		t.Fatalf("API node addresses have type %T", node["addresses"])
	}

	ips := make([]string, 0, len(addresses))
	for _, entry := range addresses {
		ip, ok := entry.(string)
		if !ok {
			t.Fatalf("API node address has type %T", entry)
		}

		ips = append(ips, ip)
	}

	cells["ip"] = strings.Join(ips, ", ")

	attrs, ok := node["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("API node attributes have type %T", node["attributes"])
	}

	cells["public-ip"] = "-"

	if value, present := attrs["ip:publicAddress"]; present {
		ip, ok := value.(string)
		if !ok {
			t.Fatalf("API public address has type %T", value)
		}

		cells["public-ip"] = cmp.Or(ip, "-")
	}

	return cells
}

func checkProjectedCells(rt *rapid.T, words, want []string, output string, gap *regexp.Regexp, nodes []map[string]string) {
	rt.Helper()

	headers := make([]string, len(want))
	for i, name := range want {
		headers[i] = strings.ToUpper(strings.ReplaceAll(name, "-", " "))
	}

	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != len(nodes)+1 || !slices.Equal(gap.Split(lines[0], -1), headers) {
		rt.Fatalf("edit %v: header %q, rows %d; want %q, rows %d", words, lines[0], len(lines)-1, headers, len(nodes))
	}

	for i, row := range nodes {
		patterns := make([]string, len(want))
		for j, name := range want {
			value, ok := row[name]
			if !ok {
				rt.Fatalf("fixture has no expected value for column %s", name)
			}

			patterns[j] = regexp.QuoteMeta(value)
		}
		// A cell can contain the same spaces that separate columns.
		for len(patterns) > 0 && patterns[len(patterns)-1] == "" {
			patterns = patterns[:len(patterns)-1]
		}

		pattern := regexp.MustCompile("^" + strings.Join(patterns, " {2,}") + "$")
		if !pattern.MatchString(lines[i+1]) {
			rt.Logf("expected cell patterns %q, got %q", patterns, lines[i+1])
			rt.Fatalf("edit %v: row %d differs from API", words, i)
		}
	}
}

// Single-column output preserves the whole cell, even when its contents resemble padding.
//
//nolint:gosmopolitan // OS strings can contain arbitrary scripts.
func TestRapidNodeFieldValues(t *testing.T) {
	f := newFixture(t, true)
	fleet(t, f)
	ids, base := rawFixtureList(t, f, "nodes", nodesPath)
	socket := filepath.Join(filepath.Dir(f.srv.SocketPath), "projection.sock")
	serve := rawListServer(t, "nodes", nodesPath, socket)

	var differentBools, presentKeys, nullKeys, spacedValues, pages, edgeSpaces, emptyOS, emptyIPs, severalIPs int

	rapid.Check(t, func(rt *rapid.T) {
		count := rapid.IntRange(1, len(ids)).Draw(rt, "nodes")
		size := rapid.IntRange(1, count).Draw(rt, "page size")
		columns := []string{"os", "ephemeral", "update-available", "auth-key", "ip"}
		rows := make([]map[string]json.RawMessage, 0, count)

		cells := make([]map[string]string, 0, count)
		for _, id := range ids[:count] {
			row := maps.Clone(base[id])
			labels := []string{"Linux", " Linux", "Linux ", "  Linux  ", "", "Example  Linux", "Example   Linux", "Plan  9", "日本語  Linux", "FreeBSD"}
			words := rapid.SliceOfN(rapid.SampledFrom([]string{"Linux", "OS", "NT", "日本語", "Ω", "64", "9"}), 1, 4)
			osName := rapid.OneOf(rapid.SampledFrom(labels), rapid.Map(words, func(v []string) string { return strings.Join(v, "  ") })).Draw(rt, "OS")
			ephemeral := rapid.Bool().Draw(rt, "ephemeral")
			update := rapid.Bool().Draw(rt, "update available")

			ips := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"192.0.2.1", "198.51.100.2", "2001:db8::1"}), 0, 3, func(ip string) string { return ip }).Draw(rt, "addresses")
			if len(ips) == 0 {
				ips = []string{}
				emptyIPs++
			}

			if len(ips) > 1 {
				severalIPs++
			}

			if osName == "" {
				emptyOS++
			}

			if osName != strings.TrimSpace(osName) {
				edgeSpaces++
			}

			vals := map[string]any{"addresses": ips, "os": osName, "isEphemeral": ephemeral, "updateAvailable": update, "authKeyId": nil}
			yesNo := map[bool]string{false: "no", true: "yes"}
			cell := map[string]string{"ip": strings.Join(ips, ", "), "os": cmp.Or(osName, "-"), "ephemeral": yesNo[ephemeral], "update-available": yesNo[update], "auth-key": "-"}

			if rapid.Bool().Draw(rt, "key present") {
				keyID := strconv.Itoa(rapid.IntRange(1, 99).Draw(rt, "key ID"))
				vals["authKeyId"] = keyID
				cell["auth-key"] = keyID
				presentKeys++
			} else {
				nullKeys++
			}

			for k, v := range vals {
				data, err := json.Marshal(v)
				if err != nil {
					rt.Fatal(err)
				}

				row[k] = data
			}

			rows = append(rows, row)
			cells = append(cells, cell)

			if ephemeral != update {
				differentBools++
			}

			if strings.Contains(osName, "  ") {
				spacedValues++
			}
		}

		order := rapid.Permutation(columns).Draw(rt, "column order")

		serve(rows, size)

		if size < count {
			pages++
		}

		run := func(value string) result {
			return f.run(t, cliCase{args: "nodes list --columns=" + value, pageSize: size, release: "0.30.1", env: []string{"HEADSCALE_UNIX_SOCKET=" + socket}})
		}
		for _, col := range columns {
			got := run(col)
			want := make([]string, 1, len(cells)+1)

			want[0] = strings.ToUpper(strings.ReplaceAll(col, "-", " "))
			for _, v := range cells {
				want = append(want, v[col])
			}

			if got.code != 0 || got.stderr != "" || got.stdout != strings.Join(want, "\n")+"\n" || len(got.answers[nodesPath]) != (count+size-1)/size {
				rt.Fatalf("single column %s differs from supplied page values", col)
			}
		}

		got := run(strings.Join(order, ","))
		if got.code != 0 || got.stderr != "" {
			rt.Fatalf("combined projection: exit=%d stderr=%q", got.code, got.stderr)
		}

		checkProjectedCells(rt, order, order, got.stdout, regexp.MustCompile(` {2,}`), cells)
	})
	t.Logf("model classes unequal-node-booleans=%d present-key-ids=%d absent-key-ids=%d spaced-os=%d multiple-node-pages=%d edge-spaces=%d empty-os=%d empty-addresses=%d several-addresses=%d", differentBools, presentKeys, nullKeys, spacedValues, pages, edgeSpaces, emptyOS, emptyIPs, severalIPs)
}

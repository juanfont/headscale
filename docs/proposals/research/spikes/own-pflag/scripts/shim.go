// Copyright 2013-2023 The Cobra Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The names below are what the copied generator functions refer to in cobra.
// Values copied from cobra completions.go, active_help.go, cobra.go.

package scripts

import (
	"bytes"
	"io"
	"regexp"
)

// Directive bits of the __complete protocol (cobra completions.go).
const (
	ShellCompDirectiveError = 1 << iota
	ShellCompDirectiveNoSpace
	ShellCompDirectiveNoFileComp
	ShellCompDirectiveFilterFileExt
	ShellCompDirectiveFilterDirs
	ShellCompDirectiveKeepOrder
	ShellCompDirectiveDefault = 0
)

const (
	ShellCompRequestCmd       = "__complete"
	ShellCompNoDescRequestCmd = "__completeNoDesc"
	activeHelpMarker          = "_activeHelp_ "
)

var configEnvVarPrefixSubstRegexp = regexp.MustCompile(`[^A-Z0-9_]`)

func activeHelpEnvVar(name string) string {
	v := []byte(name + "_ACTIVE_HELP")
	return configEnvVarPrefixSubstRegexp.ReplaceAllString(string(bytes.ToUpper(v)), "_")
}

// WriteStringAndCheck ignores the error like cobra's CheckErr would not: the
// caller's writer reports it on Close/Flush.
func WriteStringAndCheck(b io.StringWriter, s string) { _, _ = b.WriteString(s) }

// Script writes the completion script for shell, or reports false.
func Script(w io.Writer, shell, name string, desc bool) bool {
	var buf bytes.Buffer
	switch shell {
	case "bash":
		genBashComp(&buf, name, desc)
	case "zsh":
		genZshComp(&buf, name, desc)
	case "fish":
		genFishComp(&buf, name, desc)
	case "powershell":
		genPowerShellComp(&buf, name, desc)
	default:
		return false
	}
	_, _ = w.Write(buf.Bytes())
	return true
}

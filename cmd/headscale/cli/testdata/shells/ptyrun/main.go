//go:build linux || darwin

// Command ptyrun drives one interactive shell in a pseudo-terminal through
// many lines: it types the line, presses Tab once, and records what the
// shell listed and the edited line. run.sh builds and calls it.
//
//	ptyrun bash|zsh|fish LINESFILE
//
// SHELL_BIN names the shell, SETUP is shell code run once first. LINESFILE
// holds one line per row, ending in "|" where the cursor stands. It prints
// one block per line: LINE, LISTED (the screen after Tab, cleaned), FINAL
// (the edited line, echoed between brackets so that a space added by the
// completion shows).
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ansi  = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>]|\r`)
	final = regexp.MustCompile(`(?m)^\[.*\]$`)
)

func main() {
	err := run(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(shell, linesFile string) error {
	lines, err := readLines(linesFile)
	if err != nil {
		return err
	}

	bin, setup := os.Getenv("SHELL_BIN"), os.Getenv("SETUP")
	args := map[string][]string{
		"bash": {"--norc", "--noprofile", "-i"},
		"zsh":  {"-f", "-i"},
		"fish": {"--no-config", "-i"},
	}[shell]

	master, slave, err := openPTY()
	if err != nil {
		return err
	}

	cmd := exec.Command(bin, args...)
	// exec keeps the last of a doubled variable.
	cmd.Env = append(os.Environ(), "TERM=dumb", "PS1=$ ", "INPUTRC=/dev/null", "COLUMNS=200", "LINES=50")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}

	err = cmd.Start()
	if err != nil {
		return err
	}

	slave.Close()

	t := newTerm(master)
	send := func(s string) { _, _ = master.WriteString(s) }

	t.read(1500*time.Millisecond, nil)
	send(setup + "\n")
	t.read(2*time.Second, nil)

	out := bufio.NewWriter(os.Stdout)

	for n, line := range lines {
		send(line + "\t")
		// The completion answers within the quiet time; the shell then waits.
		listed := t.read(1500*time.Millisecond, nil)

		pre, post := "X='", "'; printf '[%s]\\n' \"$X\"\n"
		if shell == "fish" {
			pre, post = "set X '", "'; printf '[%s]\\n' $X\n"
		}

		send("\x01" + pre + "\x05" + post)

		m := final.FindAllString(t.read(0, final), -1)
		// The prompt follows the printf; let it come before the next line.
		t.read(300*time.Millisecond, nil)

		if n > 0 {
			fmt.Fprintln(out)
		}

		got := "??"
		if len(m) > 0 {
			got = m[len(m)-1]
		}

		fmt.Fprintln(out, "LINE: "+line+"|")
		fmt.Fprintln(out, "LISTED: ["+strings.ReplaceAll(strings.ReplaceAll(listed, "\x07", "<BEL>"), "\n", " / ")+"]")
		fmt.Fprintln(out, "FINAL: "+got)
		out.Flush()
	}

	// A shell that died on the way leaves "??" above; fail too.
	var ws unix.WaitStatus

	pid, err := unix.Wait4(cmd.Process.Pid, &ws, unix.WNOHANG, nil)
	if err != nil || pid != 0 {
		return fmt.Errorf("%s exited before the last line", shell)
	}

	return cmd.Process.Kill()
}

// readLines is every row of path that is not blank, without its newline
// and its last character, the "|" of the cursor.
func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lines []string

	for l := range strings.Lines(string(b)) {
		if strings.TrimSpace(l) == "" {
			continue
		}

		l = strings.TrimRight(l, "\n")
		lines = append(lines, l[:len(l)-1])
	}

	return lines, nil
}

// term is the output of the shell, pumped from the master side so that a
// read can wait for it with a deadline.
type term struct {
	chunks chan []byte
	closed bool
}

func newTerm(master *os.File) *term {
	t := &term{chunks: make(chan []byte, 64)}

	go func() {
		defer close(t.chunks)

		for {
			buf := make([]byte, 65536)

			n, err := master.Read(buf)
			if n > 0 {
				t.chunks <- buf[:n]
			}

			if err != nil {
				return
			}
		}
	}()

	return t
}

// read reads until no byte came for quiet, or until the cleaned output
// matches until; it gives up after 15 seconds.
func (t *term) read(quiet time.Duration, until *regexp.Regexp) string {
	var out []byte

	clean := func() string { return ansi.ReplaceAllString(strings.ToValidUTF8(string(out), "�"), "") }
	end := time.Now().Add(15 * time.Second)
	last := time.Now()

	for !t.closed && time.Now().Before(end) {
		select {
		case b, ok := <-t.chunks:
			if !ok {
				t.closed = true

				return clean()
			}

			out = append(out, b...)
			last = time.Now()

			if until != nil && until.MatchString(clean()) {
				return clean()
			}
		case <-time.After(50 * time.Millisecond):
			if until == nil && time.Since(last) > quiet {
				return clean()
			}
		}
	}

	return clean()
}

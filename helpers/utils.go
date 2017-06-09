package helpers

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/abh/geoip"
)

// Pipeline strings together the given exec.Cmd commands in a similar fashion
// to the Unix pipeline.  Each command's standard output is connected to the
// standard input of the next command, and the output of the final command in
// the pipeline is returned, along with the collected standard error of all
// commands and the first error found (if any).
//
// To provide input to the pipeline, assign an io.Reader to the first's Stdin.
func Pipeline(cmds ...*exec.Cmd) (pipeLineOutput, collectedStandardError []byte, pipeLineError error) {
	// Require at least one command
	if len(cmds) < 1 {
		return nil, nil, nil
	}

	// Collect the output from the command(s)
	var output bytes.Buffer
	var stderr bytes.Buffer

	last := len(cmds) - 1
	for i, cmd := range cmds[:last] {
		var err error
		// Connect each command's stdin to the previous command's stdout
		if cmds[i+1].Stdin, err = cmd.StdoutPipe(); err != nil {
			return nil, nil, err
		}
		// Connect each command's stderr to a buffer
		cmd.Stderr = &stderr
	}

	// Connect the output and error for the last command
	cmds[last].Stdout, cmds[last].Stderr = &output, &stderr

	// Start each command
	for _, cmd := range cmds {
		if err := cmd.Start(); err != nil {
			return output.Bytes(), stderr.Bytes(), err
		}
	}

	// Wait for each command to complete
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			return output.Bytes(), stderr.Bytes(), err
		}
	}

	// Return the pipeline output and the collected standard error
	return output.Bytes(), stderr.Bytes(), nil
}

func SplitFieldsBySep(sep string, input string, output *[]string) {
	input = strings.Replace(input, `"`, "", -1)
	sub := strings.Split(input, sep)
	if len(sub) > 1 {
		*output = append(*output, fmt.Sprintf("%s", strings.Join(sub[1:], "")))
	} else {
		*output = append(*output, fmt.Sprintf("%s", strings.Join(sub[0:], "")))
	}
}

func InitializeGeoIP() *geoip.GeoIP {
	file := "/usr/share/GeoIP/GeoIPCity.dat"

	gi, err := geoip.Open(file)
	if err != nil {
		fmt.Printf("Could not open GeoIP database\n")
	}
	return gi
}

func ParseUnixTimestamp(timestamp string) (*time.Time, error) {
	//we discard nanoseconds info
	i, err := strconv.ParseInt(timestamp[0:10], 10, 64)

	if err != nil {
		return nil, err
	}
	tm := time.Unix(i, 0)
	return &tm, err
}

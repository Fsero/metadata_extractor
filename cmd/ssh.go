// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"bitbucket.org/fseros/metadata_ssh_extractor/helpers"

	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/asaskevich/govalidator"
	"github.com/spf13/cobra"
)

var dataFile []string

type AttackerData struct {
	UnixTime    string
	IP          string
	User        string
	Password    string
	Successful  bool
	ContainerID string
}

//{"evt.cpu":0,"evt.dir":"<","evt.info":"res=10 data=\n123456 ","evt.num":191296,"evt.outputtime":1496213719701061056,"evt.type":"write","proc.name":"sshd","thread.tid":21053}

type Trace struct {
	ContainerId         string `json:"container.id",omitempty`
	ContainerName       string `json:"container.name",omitempty`
	EventCpu            int    `json:"evt.cpu"`
	EventDir            string `json:"evt.dir"`
	EventInfo           string `json:"evt.info"`
	EventNumber         int    `json:"evt.num"`
	EventOutputUnixTime int64  `json:"evt.outputtime"`
	EventType           string `json:"evt.type"`
	ProcName            string `json:"proc.name"`
	ThreadTid           int    `json:"thread.tid"`
	ThreadVTid          int    `json:"thread.vtid",omitempty`
}

type ByUnixTime []Trace

func (a ByUnixTime) Len() int           { return len(a) }
func (a ByUnixTime) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByUnixTime) Less(i, j int) bool { return a[i].EventOutputUnixTime < a[j].EventOutputUnixTime }

type extraction struct {
	User        string
	Hostname    string
	Success     string
	Password    string
	IP          string
	ContainerID string
}

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "extracts metadata from ssh potted containers",
	Long: `Extracts metadata from sysdig captures of ssh containers. 
	this process is extremely cpu intensive and fragile, do not try at home.`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Work your own magic here
		fmt.Println("ssh called")
		for file := range dataFile {
			fmt.Printf("%+v", file)

		}
		fmt.Printf("%+v", args)
		var loginAttempts []AttackerData
		if !checkSysdigAvailable() {
			log.Fatal("we cannot find sysdig")
		}
		for _, f := range args {
			if _, err := os.Stat(f); os.IsNotExist(err) {
				log.Debugf(" %s does not exist", f)
				continue
			}
			loginAttempts = extractAttackerData(f)
		}
		for _, attempt := range loginAttempts {
			log.Infof("%+v", attempt)
		}

	},
}

func init() {

	sshCmd.Flags().StringSliceVarP(&dataFile, "file", "f", make([]string, 1), "file to process")
	RootCmd.AddCommand(sshCmd)
	log.SetLevel(log.InfoLevel)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sshCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sshCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}

func checkSysdigAvailable() bool {
	_, err := exec.Command("/usr/bin/sysdig", "-h").Output()
	if err != nil {
		log.Fatal(err)
		return false
	}
	return true
}

func splitFieldsBySep(sep string, input string, output *[]string) {
	input = strings.Replace(input, `"`, "", -1)
	sub := strings.Split(input, sep)
	if len(sub) > 1 {
		*output = append(*output, fmt.Sprintf("%s", strings.Join(sub[1:], "")))
	} else {
		*output = append(*output, fmt.Sprintf("%s", strings.Join(sub[0:], "")))
	}
}

func validateCapture(capture extraction) bool {
	if !govalidator.IsIP(capture.IP) {
		log.Debugf("[validateCapture] invalid ip %s", capture.IP)
		return false
	}
	if !govalidator.IsASCII(capture.User) {
		log.Debugf("[validateCapture] invalid user %s", capture.User)
		return false
	}
	if !((capture.Success != "") && (capture.Success == "success" || capture.Success == "failed")) {

		log.Debugf("[validateCapture] invalid success state %s", capture.Success)
		return false
	}

	if len(capture.Password) == 0 {
		log.Debug("[validateCapture] no password captured ")
		return false
	}
	if len(capture.Password) > 30 {
		log.Debug("[validateCapture] invalid password")
		return false
	}
	return true
}

func extractLoginAttempt(capture *extraction, fields []string) {

	var subfields []string
	subfields = make([]string, 1)

	for key, field := range fields {
		if key == 0 {
			continue
		}
		if key == 2 {
			subfields = append(subfields, fmt.Sprintf("%s", field))
			continue
		}
		splitFieldsBySep("=", field, &subfields)
	}
	capture.User = subfields[3]
	capture.Hostname = subfields[5]
	capture.IP = subfields[6]
	capture.Success = subfields[7]
}

func extractPassword(capture *extraction, fields []string) {
	var subfields []string
	subfields = make([]string, 1)

	for key, field := range fields {
		if key == 0 {
			continue
		}
		splitFieldsBySep("=", field, &subfields)
	}
	str := strings.Join(subfields[2:], "")
	if strings.Contains(str, "PAM:") || len(str) > 30 {
		capture.Password = "'NOTFOUND'"
	} else {
		capture.Password = subfields[2]
	}
}

func parseTraces(traces []Trace) []AttackerData {
	// on traces password appears first and then login attempt info.
	// traces should be ordered by time
	/*
		{63f6e3883d7c ssh 0 < res=10 data=
		abc123  159003 1496213704714312629 write sshd 21037 13946}
		{63f6e3883d7c ssh 0 < res=140 data=
		Lop=PAM:authentication acct="root" exe="/usr/sbin/sshd" hostname=107.160.16.221 addr=107.160.16.221 terminal=ssh res=success  159104 1496213704727977064 sendto sshd 21036 13945}

	*/
	var LoginAttempts []AttackerData
	LoginAttempts = make([]AttackerData, 0)
	loginAttemptRegexp := regexp.MustCompile(`(res=\d+) (data=.*PAM:authentication.*)(acct=.*)(exe=.*)(hostname=.*)(addr=[\d{1,3}\.]+).*(res=failed|success).*`)
	passwordInputRegexp := regexp.MustCompile(`(res=\d+) (data=.*)`)

	var capture extraction
	for _, trace := range traces {
		str := strings.Replace(trace.EventInfo, "\n", "", -1)
		if capture.ContainerID != "" && capture.ContainerID != trace.ContainerId {
			capture.ContainerID = trace.ContainerId
			capture = extraction{}
		} else {
			capture.ContainerID = trace.ContainerId
		}
		log.Debugf("[parseTraces] line to parse %s", str)
		log.Debugf("[parseTraces] original trace %s", trace)

		// no password captured yet, so processing it.
		if capture.Password == "" && passwordInputRegexp.MatchString(str) {
			fields := passwordInputRegexp.FindStringSubmatch(str)
			extractPassword(&capture, fields)
			log.Debugf("[parseTraces] from password %+v", capture)
		}
		if loginAttemptRegexp.MatchString(str) {
			fields := loginAttemptRegexp.FindStringSubmatch(str)
			extractLoginAttempt(&capture, fields)
			log.Debugf("[parseTraces] from login %+v", capture)

		}

		if validateCapture(capture) {
			var data AttackerData
			data.IP = capture.IP
			data.Password = capture.Password
			data.Successful = (capture.Success == "success")
			data.UnixTime = (strconv.FormatInt(trace.EventOutputUnixTime, 10)[0:13])
			data.ContainerID = capture.ContainerID
			log.Debugf("[parseTraces] attempt added %+v", data)
			LoginAttempts = append(LoginAttempts, data)
			capture = extraction{}
		} else {
			log.Debugf("Attempt not valid! %+v", capture)
		}
	}
	return LoginAttempts
}

func extractAttackerData(file string) []AttackerData {
	//sysdig -j -A -F -r srv02.superprivyhosting.com.2017-05-31-06-54.part2 container.id!=host and fd.num=4 and evt.is_io_write=true and evt.dir = '<' and proc.name=sshd | egrep -B1 PAM:

	sysdig := exec.Command("/usr/bin/sysdig", "-pc", "-j", "-F", "-A", "-r", file, "container.id!=host", "and", "fd.num=4", "and", "evt.is_io_write=true", "and", "evt.dir", "=", "'<'", "and", "proc.name=sshd")
	egrep := exec.Command("egrep", "-B1", "PAM:")
	removedashes := exec.Command("egrep", "-v", "\\-")
	output, _, err := helpers.Pipeline(sysdig, egrep, removedashes)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("%s", output)
	var traces []Trace

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var tr Trace
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal([]byte(line), &tr); err != nil {
			log.Fatal(err)
		}
		traces = append(traces, tr)

	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	log.Infof("num of traces %s", len(traces))
	sort.Sort(ByUnixTime(traces))
	LoginAttempts := parseTraces(traces)
	return LoginAttempts
}

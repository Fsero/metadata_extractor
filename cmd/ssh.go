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
	"strings"
	"time"

	"bitbucket.org/fseros/metadata_ssh_extractor/helpers"

	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
)

var dataFile []string

type AttackerData struct {
	Date       time.Time
	IP         string
	User       string
	Password   string
	Action     string
	Successful bool
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

		if !checkSysdigAvailable() {
			log.Fatal("we cannot find sysdig")
		}
		for _, f := range args {
			if _, err := os.Stat(f); os.IsNotExist(err) {
				log.Debugf(" %s does not exist", f)
				continue
			}
			extractAttackerData(f)
		}

	},
}

func init() {

	sshCmd.Flags().StringSliceVarP(&dataFile, "file", "f", make([]string, 1), "file to process")
	RootCmd.AddCommand(sshCmd)

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

func parseTrace(trace Trace) AttackerData {
	var data AttackerData
	re := regexp.MustCompile(`(res=\d+) (data=.*PAM.*)(acct=.*)(exe=.*)(hostname=.*)(addr=[\d{1,3}\.]+).*(res=failed|success).*`)
	str := strings.Replace(trace.EventInfo, "\n", "", -1)
	fmt.Println(str)
	if re.MatchString(str) {
		log.Info("found")
		fields := re.FindStringSubmatch(str)
		log.Info(fields)
		for _, field := range fields {
			field = strings.Replace(field, `"`, "", -1)
			subfields := strings.Split(field, "=")
			if len(subfields) > 1 {
				log.Info(subfields[1])
			}
		}
	} else {
		//re2 := regexp.MustCompile(`(res=\d+) (data=.*PAM.*)(acct=.*)(exe=.*)(hostname=.*)(addr=[\d{1,3}\.]+).*(res=failed|success).*`)

		log.Info("not found")

	}
	return data
}

func extractAttackerData(file string) AttackerData {
	//sysdig -j -A -F -r srv02.superprivyhosting.com.2017-05-31-06-54.part2 container.id!=host and fd.num=4 and evt.is_io_write=true and evt.dir = '<' and proc.name=sshd | egrep -B1 PAM:

	sysdig := exec.Command("/usr/bin/sysdig", "-j", "-F", "-A", "-r", file, "container.id!=host", "and", "fd.num=4", "and", "evt.is_io_write=true", "and", "evt.dir", "=", "'<'", "and", "proc.name=sshd")
	egrep := exec.Command("egrep", "-B1", "PAM:")
	removedashes := exec.Command("egrep", "-v", "\\-")
	output, _, err := helpers.Pipeline(sysdig, egrep, removedashes)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("%s", output)
	var traces []Trace
	//st := `{"evt.cpu":0,"evt.dir":"<","evt.info":"res=136 data=\nLop=PAM:authentication acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=62.112.11.94 addr=62.112.11.94 terminal=ssh res=failed ","evt.num":623140,"evt.outputtime":1496213939947218324,"evt.type":"sendto","proc.name":"sshd","thread.tid":21194}`

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
	for _, trace := range traces {
		parseTrace(trace)

	}
	return AttackerData{}
}

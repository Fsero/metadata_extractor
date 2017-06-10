package parsers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"

	"bitbucket.org/fseros/metadata_ssh_extractor/helpers"
)

func Init() bool {
	_, err := exec.Command("/usr/bin/sysdig", "-h").Output()
	if err != nil {
		log.Fatal(err)
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
		helpers.SplitFieldsBySep("=", field, &subfields)
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
		helpers.SplitFieldsBySep("=", field, &subfields)
	}
	str := strings.Join(subfields[2:], "")
	if strings.Contains(str, "PAM:") || len(str) > 30 {
		capture.Password = "'NOTFOUND'"
	} else {
		capture.Password = subfields[2]
	}
}

func parseTraces(traces []Trace) []AttackerLoginAttempt {
	// on traces password appears first and then login attempt info.
	// traces should be ordered by time
	/*
		{63f6e3883d7c ssh 0 < res=10 data=
		abc123  159003 1496213704714312629 write sshd 21037 13946}
		{63f6e3883d7c ssh 0 < res=140 data=
		Lop=PAM:authentication acct="root" exe="/usr/sbin/sshd" hostname=107.160.16.221 addr=107.160.16.221 terminal=ssh res=success  159104 1496213704727977064 sendto sshd 21036 13945}

	*/
	var LoginAttempts []AttackerLoginAttempt
	LoginAttempts = make([]AttackerLoginAttempt, 0)
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
			var data AttackerLoginAttempt
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

func ExtractAttackerLoginAttempt(file string) []AttackerLoginAttempt {
	//sysdig -j -A -F -r srv02.superprivyhosting.com.2017-05-31-06-54.part2 container.id!=host and fd.num=4 and evt.is_io_write=true and evt.dir = '<' and proc.name=sshd | egrep -B1 PAM:

	sysdig := exec.Command("/usr/bin/sysdig", "-pc", "-j", "-F", "-A", "-r", file, "container.id!=host", "and", "fd.num=4", "and", "evt.is_io_write=true", "and", "evt.dir", "=", "'<'", "and", "proc.name=sshd")
	egrep := exec.Command("egrep", "-B1", "PAM:")
	removedashes := exec.Command("egrep", "-v", "\\-")
	output, _, err := helpers.Pipeline(sysdig, egrep, removedashes)
	if err != nil {
		log.Fatal(err)
	}
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
	log.Debugf("num of traces %s", len(traces))
	sort.Sort(ByUnixTime(traces))
	LoginAttempts := parseTraces(traces)
	return LoginAttempts
}

//it reads raw data from command and outputs
//a formatted list of lines
func parseActivities(lines []byte) []string {
	headerRegexp := regexp.MustCompile(`(\d+) (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{9}) (\w+)@(\w+)\)`)
	scanner := bufio.NewScanner(bytes.NewReader(lines))
	var buffer bytes.Buffer
	AttackerActivityLog := make([]string, 0)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if headerRegexp.MatchString(line) {
			if buffer.Len() > 0 {
				AttackerActivityLog = append(AttackerActivityLog, buffer.String())
				buffer.Reset()
			}
			buffer.WriteString(line)
		} else {
			buffer.WriteString(line)
		}

	}
	return AttackerActivityLog
}
func ExtractAttackerActivity(file string) []AttackerActivity {

	//sysdig -pc -r test/srv02.superprivyhosting.com.2017-05-31-06-54.part2 -c spy_users '100 disable_color' container.id != host | grep -v 'sshd -R'
	sysdig := exec.Command("/usr/bin/sysdig", "-pc", "-c", "spy_users", "-r", file, "container.id!=host")
	egrep := exec.Command("egrep", "-v", `sshd.*R`)

	output, _, err := helpers.Pipeline(sysdig, egrep)
	if err != nil {
		log.Fatal(err)
	}
	AttackerActivityLog := parseActivities(output)
	AttackerActivityEntries := make([]AttackerActivity, 0)
	ActivityRegexp := regexp.MustCompile(`(\d+) (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{9}) (\w+)@(\w+)\) (.*)`)
	for _, logentry := range AttackerActivityLog {
		subfields := ActivityRegexp.FindStringSubmatch(logentry)
		if len(subfields) == 0 {
			continue
		}
		var entry activitylog
		entry.PID = subfields[1]
		entry.User = subfields[3]
		entry.Datetime = subfields[2]
		entry.ContainerID = subfields[4]
		entry.Command = subfields[5]
		log.Debugf("entry parsed %+v", entry)
		if validateEntry(entry) {
			log.Debugf("entry validated")
			var data AttackerActivity
			data.Activity = entry.Command
			data.ContainerID = entry.ContainerID
			data.SourceFile = file
			data.PID = entry.PID
			data.User = entry.User
			data.Datetime = entry.Datetime
			AttackerActivityEntries = append(AttackerActivityEntries, data)

		}

	}
	return AttackerActivityEntries
}
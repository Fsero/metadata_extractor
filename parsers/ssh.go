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

	"github.com/Sirupsen/logrus"

	"bitbucket.org/fseros/metadata_extractor/helpers"
)

var loginAttemptRegexp = regexp.MustCompile(`(res=\d+) (data=.*PAM:authentication.*)(acct=.*)(exe=.*)(hostname=.*)(addr=[\d{1,3}\.]+).*(res=failed|success).*`)
var passwordInputRegexp = regexp.MustCompile(`(res=\d+) (data=.\w+.*)`)

func Init() bool {
	_, err := exec.Command("/usr/bin/sysdig", "-h").Output()
	if err != nil {
		logrus.Fatalf("Unable to initialize ssh parsers %s", err)
		return false
	}
	return true
}

func extractLoginAttempt(fields []string) AttackerLoginAttempt {

	var capture AttackerLoginAttempt
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
	capture.Successful = subfields[7] == "success"
	return capture
}

func extractPassword(fields []string) AttackerLoginAttempt {
	var capture AttackerLoginAttempt
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
	return capture
}

func matchesRegexpTrace(trace Trace, re *regexp.Regexp) bool {

	str := strings.Replace(trace.EventInfo, "\n", "", -1)
	return re.MatchString(str)

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
	var m map[int][]Trace
	m = make(map[int][]Trace, 0)
	for _, trace := range traces {
		logrus.Debugf("[parseTraces] readed %+v", trace)
		tr := m[trace.ThreadTid]
		if tr == nil {
			tr = make([]Trace, 0)
		}
		tr = append(tr, trace)
		m[trace.ThreadTid] = tr
	}

	var keys []int
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var LoginAttempts []AttackerLoginAttempt
	LoginAttempts = make([]AttackerLoginAttempt, 0)

	for k := 0; k < len(keys); k += 2 {
		var trace0, trace1 []Trace
		trace0 = m[keys[k]]
		logrus.Debugf("%d %+v\n", keys[k], m[keys[k]])
		if k+1 < len(keys) {
			trace1 = m[keys[k+1]]
			logrus.Debugf("%d %+v\n", keys[k+1], m[keys[k+1]])
		}

		switch {
		case len(trace0) <= 0 && len(trace1) <= 0:
			logrus.Fatalf("[parseTraces] invalid block, something nasty happened")

		case len(trace0) <= 0 && len(trace1) > 0:
			trace0, trace1 = trace1, trace0
			logrus.Debugf("[parseTraces] swapping blocks, something weird happened")
		}

		for i := range trace0 {
			var elem0, elem1 Trace
			if i < len(trace0) {
				elem0 = trace0[i]
			} else {
				elem0 = Trace{}
			}
			if i < len(trace1) {
				elem1 = trace1[i]
			} else {
				elem1 = Trace{}
			}

			var capture, p, l AttackerLoginAttempt
			logrus.Debugf("elem0 %+v elem1 %+v", elem0, elem1)
			switch {
			case matchesRegexpTrace(elem0, passwordInputRegexp) && matchesRegexpTrace(elem1, loginAttemptRegexp):

				str := strings.Replace(elem0.EventInfo, "\n", "", -1)
				fields := passwordInputRegexp.FindStringSubmatch(str)
				p = extractPassword(fields)
				str = strings.Replace(elem1.EventInfo, "\n", "", -1)
				fields = loginAttemptRegexp.FindStringSubmatch(str)
				l = extractLoginAttempt(fields)
				l.UnixTime = (strconv.FormatInt(elem1.EventOutputUnixTime, 10)[0:13])
				logrus.Debug("elem0 == pass and elem1 == login")

			case matchesRegexpTrace(elem1, passwordInputRegexp) && matchesRegexpTrace(elem0, loginAttemptRegexp):
				str := strings.Replace(elem1.EventInfo, "\n", "", -1)
				fields := passwordInputRegexp.FindStringSubmatch(str)
				p = extractPassword(fields)
				str = strings.Replace(elem0.EventInfo, "\n", "", -1)
				fields = loginAttemptRegexp.FindStringSubmatch(str)
				l = extractLoginAttempt(fields)
				l.UnixTime = (strconv.FormatInt(elem0.EventOutputUnixTime, 10)[0:13])
				logrus.Debug("elem1 == pass and elem0 == login")

			case matchesRegexpTrace(elem0, passwordInputRegexp) && matchesRegexpTrace(elem1, passwordInputRegexp):
				logrus.Debugf("[parseTraces] two password blocks, Discarding")
				continue

			case matchesRegexpTrace(elem1, loginAttemptRegexp) && matchesRegexpTrace(elem0, loginAttemptRegexp):
				logrus.Debugf("[parseTraces] two login blocks, Discarding")
				continue

			default:
				if elem0.ContainerID == "" {
					switch {
					case matchesRegexpTrace(elem1, loginAttemptRegexp):
						str := strings.Replace(elem1.EventInfo, "\n", "", -1)
						fields := loginAttemptRegexp.FindStringSubmatch(str)
						l = extractLoginAttempt(fields)
						l.UnixTime = (strconv.FormatInt(elem1.EventOutputUnixTime, 10)[0:13])
						p.Password = `'NOTFOUND'`
						logrus.Debugf("[parseTraces] not password found :-(")

						logrus.Debug("elem0 == [] and elem1 == login")
					}
				} else if elem1.ContainerID == "" {
					switch {
					case matchesRegexpTrace(elem0, loginAttemptRegexp):
						str := strings.Replace(elem0.EventInfo, "\n", "", -1)
						fields := loginAttemptRegexp.FindStringSubmatch(str)
						l = extractLoginAttempt(fields)
						l.UnixTime = (strconv.FormatInt(elem0.EventOutputUnixTime, 10)[0:13])
						p.Password = `'NOTFOUND'`
						logrus.Debugf("[parseTraces] not password found :-(")

						logrus.Debug("elem0 == login and elem1 == [] ")
					}
				} else {
					logrus.Fatalf("[parseTraces] unexpected error, we didnt receive any block %+v %+v", trace0, trace1)
				}

			}
			capture.Password = p.Password
			capture.ContainerID = l.ContainerID
			capture.Hostname = l.Hostname
			capture.IP = l.IP
			capture.Successful = l.Successful
			capture.UnixTime = l.UnixTime
			capture.User = l.User

			if validateCapture(capture) {
				logrus.Debugf("[parseTraces] adding capture %+v", capture)
				LoginAttempts = append(LoginAttempts, capture)
			}

		}
	}
	return LoginAttempts
}

func ExtractAttackerLoginAttempt(file string) []AttackerLoginAttempt {
	//sysdig -j -A -F -r srv02.superprivyhosting.com.2017-05-31-06-54.part2 container.id!=host and fd.num=4 and evt.is_io_write=true and evt.dir = '<' and proc.name=sshd | egrep -B1 PAM:

	sysdig := exec.Command("/usr/bin/sysdig", "-pc", "-j", "-F", "-A", "-r", file, "container.id!=host", "and", "fd.num=4", "and", "evt.is_io_write=true", "and", "evt.dir", "=", "'<'", "and", "proc.name=sshd")
	egrep := exec.Command("egrep", "-B1", "PAM:")
	removedashes := exec.Command("egrep", "-v", "\\-")
	output, stderr, err := helpers.Pipeline(sysdig, egrep, removedashes)
	logrus.Debug(sysdig)
	logrus.Debug(egrep)
	logrus.Debugf("STDERR: %s", stderr)
	if err != nil {
		if checkSysdigFailure(output, stderr, file) {
			logrus.Debugf("[ExtractAttackerActivity] Unable to launch sysdig %s", err)
			return nil
		}
	}
	var traces []Trace

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var tr Trace
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		logrus.Debugf("[ExtractAttackerLoginAttempt] readed \n %s", line)
		if err := json.Unmarshal([]byte(line), &tr); err != nil {
			logrus.Debugf("[ExtractAttackerLoginAttempt] Unable to get JSON %s ", err)
			logrus.Debugf("[ExtractAttackerLoginAttempt] Unable to parse trace from %s", line)
			continue
		}
		tr.EventInfo = strings.Replace(tr.EventInfo, "\n", "", -1)
		switch {
		case !loginAttemptRegexp.MatchString(tr.EventInfo) && !passwordInputRegexp.MatchString(tr.EventInfo):
			logrus.Debugf("[extractAttackerLoginAttempt] invalid trace, discarding it")
			continue
		case strings.Contains(tr.EventInfo, "ssh:notty"):
			logrus.Debugf("[extractAttackerLoginAttempt] invalid trace, discarding it")
			continue
		case loginAttemptRegexp.MatchString(tr.EventInfo) && !strings.Contains(tr.EventInfo, "PAM:authentication"):
			logrus.Debugf("[extractAttackerLoginAttempt] we are only interested on auth events from PAM")
			continue
		default:
			traces = append(traces, tr)
		}

	}
	if err := scanner.Err(); err != nil {
		logrus.Fatalf("[ExtractAttackerLoginAttempt] Unable to parse trace %s", err)
	}
	logrus.Debugf("num of traces %s", len(traces))
	sort.Sort(ByEventNumber(traces))
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

func isTraceFileOk(output, file string) bool {
	var isOk bool
	if strings.Contains(output, "Is the file truncated?") {
		isOk = false
		logrus.Debugf("looks like file is not complete, refusing to continue")
	} else if strings.Contains(output, "error reading from file") || strings.Contains(output, "unexpected end of file") {
		logrus.Debugf("looks like file is wrong, refusing to continue")
		isOk = false
	} else {
		logrus.Debugf("looks like file is fine, why are we here?")
		isOk = true
	}
	return isOk
}

func checkSysdigFailure(stdout, stderr []byte, file string) bool {
	sErr := string(stderr[:])
	sOut := string(stdout[:])
	if !isTraceFileOk(sErr, file) {
		logrus.Debugf("STDERR: %s", sErr)
		logrus.Debugf("[checkSysdigFailure] unable to read trace %s refusing to continue", file)
		return true
	} else if !isTraceFileOk(sOut, file) {
		logrus.Debugf("STDOUT: %s", sOut)
		logrus.Debugf("[checkSysdigFailure] unable to read trace %s refusing to continue", file)
		return true
	}
	return false
}

func ExtractAttackerActivity(file string) []AttackerActivity {

	//sysdig -pc -r test/srv02.superprivyhosting.com.2017-05-31-06-54.part2 -c spy_users '100 disable_color' container.id != host | grep -v 'sshd -R'
	sysdig := exec.Command("/usr/bin/sysdig", "-pc", "-c", "spy_users", "-r", file, "container.id!=host")
	egrep := exec.Command("egrep", "-v", `sshd.*R`)

	output, stderr, err := helpers.Pipeline(sysdig, egrep)
	if err != nil {
		if checkSysdigFailure(output, stderr, file) {
			logrus.Debugf("[ExtractAttackerActivity] Unable to launch sysdig %s", err)
			return nil

		}
		// if stderr is not empty, then something nasty happened if not is just an empty file
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
		logrus.Debugf("entry parsed %+v", entry)
		if validateEntry(entry) {
			logrus.Debugf("entry validated")
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

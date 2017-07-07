package parsers

type Trace struct {
	ContainerID         string `json:"container.id",omitempty`
	ContainerName       string `json:"container.name",omitempty`
	EventCPU            int    `json:"evt.cpu"`
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
type ByEventNumber []Trace

func (a ByUnixTime) Len() int      { return len(a) }
func (a ByUnixTime) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByUnixTime) Less(i, j int) bool {

	if a[i].EventOutputUnixTime == a[j].EventOutputUnixTime {
		if a[i].ThreadTid == a[j].ThreadTid {
			if a[i].ThreadVTid == a[j].ThreadVTid {
				return a[i].EventNumber < a[j].EventNumber
			}
			return a[i].ThreadVTid < a[j].ThreadVTid
		}
		return a[i].ThreadTid < a[j].ThreadTid
	}
	return a[i].EventOutputUnixTime < a[j].EventOutputUnixTime

}

func (a ByEventNumber) Len() int      { return len(a) }
func (a ByEventNumber) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByEventNumber) Less(i, j int) bool {
	switch {
	case a[i].EventOutputUnixTime < a[j].EventOutputUnixTime:
		// p < q, so we have a decision.
		return true
	case a[i].EventOutputUnixTime > a[j].EventOutputUnixTime:
		// p > q, so we have a decision.
		return false
	}
	return a[i].ThreadTid < a[j].ThreadTid
}

type AttackerLoginAttempt struct {
	UnixTime    string
	IP          string
	User        string
	Password    string
	Successful  bool
	ContainerID string
	Hostname    string
}

type AttackerActivity struct {
	ContainerID string
	SourceFile  string
	User        string
	PID         string
	Datetime    string
	Activity    string
}
type activitylog struct {
	PID         string
	User        string
	ContainerID string
	Command     string
	Datetime    string
}

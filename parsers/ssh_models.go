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

func (a ByUnixTime) Len() int           { return len(a) }
func (a ByUnixTime) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByUnixTime) Less(i, j int) bool { return a[i].EventOutputUnixTime < a[j].EventOutputUnixTime }

type AttackerLoginAttempt struct {
	UnixTime    string
	IP          string
	User        string
	Password    string
	Successful  bool
	ContainerID string
}

type AttackerActivity struct {
	ContainerID string
	SourceFile  string
	User        string
	PID         string
	Datetime    string
	Activity    string
}

type extraction struct {
	User        string
	Hostname    string
	Success     string
	Password    string
	IP          string
	ContainerID string
}
type activitylog struct {
	PID         string
	User        string
	ContainerID string
	Command     string
	Datetime    string
}

package config

type GlobalConfig struct {
	CfgFile            string
	Writer             OutputWriter
	CfgWriters         string
	EShost             string
	ESport             string
	ProbeID            string
	SinkerAPIURL       string
	Follow             bool
	Tracespath         string
	SyncBandwidthLimit string
	Probe              *Probe
	Verbose            bool
}

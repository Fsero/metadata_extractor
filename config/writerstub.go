package config

import (
	"bitbucket.org/fseros/metadata_ssh_extractor/parsers"
	"github.com/abh/geoip"
)

type OutputWriter interface {
	WriteAttackerActivies(activities []parsers.AttackerActivity, cfg *GlobalConfig) error
	WriteAttackerLoginAttempts(attempts []parsers.AttackerLoginAttempt, geoIP *geoip.GeoIP, cfg *GlobalConfig) error
}

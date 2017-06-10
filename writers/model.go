package writers

import (
	"bitbucket.org/fseros/metadata_ssh_extractor/parsers"
	"github.com/abh/geoip"
)

type OutputWriter interface {
	WriteAttackerActivies(activities []parsers.AttackerActivity) error
	WriteAttackerLoginAttempts(attempts []parsers.AttackerLoginAttempt, geoIP *geoip.GeoIP) error
}

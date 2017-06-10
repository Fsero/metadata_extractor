package writers

import (
	"bitbucket.org/fseros/metadata_ssh_extractor/parsers"
	log "github.com/Sirupsen/logrus"
	"github.com/abh/geoip"
)

type CommandLineWriter struct{}

func (e CommandLineWriter) WriteAttackerActivies(activities []parsers.AttackerActivity) error {
	log.Infof("activities %s", len(activities))
	for _, entry := range activities {
		log.Infof("%+v", entry)
	}
	return nil
}

func (e CommandLineWriter) WriteAttackerLoginAttempts(attempts []parsers.AttackerLoginAttempt, geoIP *geoip.GeoIP) error {
	for _, attempt := range attempts {
		log.Infof("%+v", attempt)
	}
	return nil
}

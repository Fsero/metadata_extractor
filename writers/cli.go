package writers

import (
	"bitbucket.org/fseros/metadata_extractor/config"
	"bitbucket.org/fseros/metadata_extractor/parsers"
	"github.com/Sirupsen/logrus"
	"github.com/abh/geoip"
)

type CommandLineWriter struct{}

func (e CommandLineWriter) WriteAttackerActivies(activities []parsers.AttackerActivity, cfg *config.GlobalConfig) error {
	logrus.Infof("activities %s", len(activities))
	for _, entry := range activities {
		logrus.Infof("%+v", entry)
	}
	return nil
}

func (e CommandLineWriter) WriteAttackerLoginAttempts(attempts []parsers.AttackerLoginAttempt, geoIP *geoip.GeoIP, cfg *config.GlobalConfig) error {
	for _, attempt := range attempts {
		logrus.Infof("%+v", attempt)
	}
	return nil
}

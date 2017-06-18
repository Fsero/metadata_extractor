package parsers

import (
	"github.com/Sirupsen/logrus"
	"github.com/asaskevich/govalidator"
)

func validateEntry(entry activitylog) bool {
	if !govalidator.IsNumeric(entry.PID) {
		logrus.Debugf("[validateCapture] invalid PID %s", entry.PID)
		return false
	}
	if !govalidator.IsASCII(entry.User) {
		logrus.Debugf("[validateCapture] invalid user %s", entry.User)
		return false
	}
	if !govalidator.IsAlphanumeric(entry.ContainerID) {
		logrus.Debugf("[validateCapture] invalid ID %s", entry.ContainerID)
		return false
	}
	return true
}

func validateCapture(capture extraction) bool {
	if !govalidator.IsIP(capture.IP) {
		logrus.Debugf("[validateCapture] invalid ip %s", capture.IP)
		return false
	}
	if !govalidator.IsASCII(capture.User) {
		logrus.Debugf("[validateCapture] invalid user %s", capture.User)
		return false
	}
	if !((capture.Success != "") && (capture.Success == "success" || capture.Success == "failed")) {

		logrus.Debugf("[validateCapture] invalid success state %s", capture.Success)
		return false
	}

	if len(capture.Password) == 0 {
		logrus.Debug("[validateCapture] no password captured ")
		return false
	}
	if len(capture.Password) > 30 {
		logrus.Debug("[validateCapture] invalid password")
		return false
	}
	return true
}

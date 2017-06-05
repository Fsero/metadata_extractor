package parsers

import (
	log "github.com/Sirupsen/logrus"
	"github.com/asaskevich/govalidator"
)

func validateEntry(entry activitylog) bool {
	if !govalidator.IsNumeric(entry.PID) {
		log.Debugf("[validateCapture] invalid PID %s", entry.PID)
		return false
	}
	if !govalidator.IsASCII(entry.User) {
		log.Debugf("[validateCapture] invalid user %s", entry.User)
		return false
	}
	if !govalidator.IsAlphanumeric(entry.ContainerID) {
		log.Debugf("[validateCapture] invalid ID %s", entry.ContainerID)
		return false
	}
	return true
}

func validateCapture(capture extraction) bool {
	if !govalidator.IsIP(capture.IP) {
		log.Debugf("[validateCapture] invalid ip %s", capture.IP)
		return false
	}
	if !govalidator.IsASCII(capture.User) {
		log.Debugf("[validateCapture] invalid user %s", capture.User)
		return false
	}
	if !((capture.Success != "") && (capture.Success == "success" || capture.Success == "failed")) {

		log.Debugf("[validateCapture] invalid success state %s", capture.Success)
		return false
	}

	if len(capture.Password) == 0 {
		log.Debug("[validateCapture] no password captured ")
		return false
	}
	if len(capture.Password) > 30 {
		log.Debug("[validateCapture] invalid password")
		return false
	}
	return true
}

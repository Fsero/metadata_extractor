package writers

import "bitbucket.org/fseros/metadata_ssh_extractor/parsers"

type OutputWriter interface {
	WriteAttackerActivies(activities []parsers.AttackerActivity) error
	WriteAttackerLoginAttempts(attempts []parsers.AttackerLoginAttempt) error
}

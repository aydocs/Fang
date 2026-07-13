package engine

type Stage int

const (
	StageCrawl Stage = iota
	StageTechDetect
	StagePassive
	StagePayloadGen
	StageActive
	StageVerify
	StagePlugin
	StageReport
)

func (s Stage) String() string {
	switch s {
	case StageCrawl:
		return "CRAWL"
	case StageTechDetect:
		return "TECH_DETECT"
	case StagePassive:
		return "PASSIVE"
	case StagePayloadGen:
		return "PAYLOAD_GEN"
	case StageActive:
		return "ACTIVE"
	case StageVerify:
		return "VERIFY"
	case StagePlugin:
		return "PLUGIN"
	case StageReport:
		return "REPORT"
	default:
		return "UNKNOWN"
	}
}

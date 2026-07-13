package scanner

import "github.com/aydocs/fang/pkg/models"

type (
	Finding    = models.Finding
	Target     = models.Target
	ScanResult = models.ScanResult
	Severity   = models.Severity
	Confidence = models.Confidence
)

const (
	Info     = models.Info
	Low      = models.Low
	Medium   = models.Medium
	High     = models.High
	Critical = models.Critical
)

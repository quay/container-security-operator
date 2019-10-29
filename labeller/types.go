package labeller

import (
	"sync"

	"github.com/coreos-inc/security-labeller/secscan/quay"
)

// type PodVulnerabilityCount struct {
// 	P0        int // High
// 	P0Fixable int
// 	P1        int // Medium
// 	P1Fixable int
// 	P2        int // Low
// 	P2Fixable int
// 	P3        int // Negligible
// 	P3Fixable int
// }

type PodVulnerabilityCount struct {
	Unknown           int
	UnknownFixable    int
	Negligible        int
	NegligibleFixable int
	Low               int
	LowFixable        int
	Medium            int
	MediumFixable     int
	High              int
	HighFixable       int
	Critical          int
	CriticalFixable   int
	Defcon1           int
	Defcon1Fixable    int
}

func (c *PodVulnerabilityCount) total() int {
	return c.Unknown + c.Negligible +
		c.Low + c.Medium + c.High +
		c.Critical + c.Defcon1
}

func (c *PodVulnerabilityCount) totalFixables() int {
	return c.UnknownFixable + c.NegligibleFixable +
		c.LowFixable + c.MediumFixable + c.HighFixable +
		c.CriticalFixable + c.Defcon1Fixable
}

func (c *PodVulnerabilityCount) highestSeverity() string {
	var highest string

	switch {
	case c.Unknown > 0:
		highest = UnknownLabel
	case c.Negligible > 0:
		highest = NegligibleLabel
	case c.Low > 0:
		highest = LowLabel
	case c.Medium > 0:
		highest = MediumLabel
	case c.High > 0:
		highest = HighLabel
	case c.Critical > 0:
		highest = CriticalLabel
	case c.Defcon1 > 0:
		highest = Defcon1Label
	default:
		highest = ""
	}

	return highest
}

type lockableQuayClients struct {
	lock        sync.RWMutex
	quayClients map[string]*quay.Quay
}

func NewLockableQuayClients() *lockableQuayClients {
	lc := &lockableQuayClients{
		quayClients: make(map[string]*quay.Quay),
	}
	return lc
}

func (l *lockableQuayClients) updateClient(key string, val *quay.Quay) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.quayClients[key] = val
}

func (l *lockableQuayClients) deleteClient(key string, val *quay.Quay) {
	l.lock.Lock()
	defer l.lock.Unlock()
	delete(l.quayClients, key)
}

func (l *lockableQuayClients) getClient(key string) (*quay.Quay, bool) {
	l.lock.RLock()
	defer l.lock.RUnlock()
	val, ok := l.quayClients[key]
	return val, ok
}

type lockableVulnerabilities struct {
	lock            sync.RWMutex
	vulnerabilities map[string]*PodVulnerabilityCount
}

func NewLockableVulnerabilites() *lockableVulnerabilities {
	lv := &lockableVulnerabilities{
		vulnerabilities: make(map[string]*PodVulnerabilityCount),
	}
	return lv
}

func (l *lockableVulnerabilities) countTotalVulnerabilities() *PodVulnerabilityCount {
	vulnCount := &PodVulnerabilityCount{}
	l.lock.RLock()
	defer l.lock.RUnlock()
	for _, v := range l.vulnerabilities {
		vulnCount.Unknown += v.Unknown
		vulnCount.UnknownFixable += v.UnknownFixable
		vulnCount.Negligible += v.Negligible
		vulnCount.NegligibleFixable += v.NegligibleFixable
		vulnCount.Low += v.Low
		vulnCount.LowFixable += v.LowFixable
		vulnCount.Medium += v.Medium
		vulnCount.MediumFixable += v.MediumFixable
		vulnCount.High += v.High
		vulnCount.HighFixable += v.HighFixable
		vulnCount.Critical += v.Critical
		vulnCount.CriticalFixable += v.CriticalFixable
		vulnCount.Defcon1 += v.Defcon1
		vulnCount.Defcon1Fixable += v.Defcon1Fixable
	}
	return vulnCount
}

func (l *lockableVulnerabilities) updateVulnerability(key string, val *PodVulnerabilityCount) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.vulnerabilities[key] = val
}

func (l *lockableVulnerabilities) deleteVulnerability(key string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	delete(l.vulnerabilities, key)
}

func (l *lockableVulnerabilities) getVulnerability(key string) (*PodVulnerabilityCount, bool) {
	l.lock.RLock()
	defer l.lock.RUnlock()
	val, ok := l.vulnerabilities[key]
	return val, ok
}

package secscan

// Severity defines a standard scale for measuring the severity of a
// vulnerability.

const (
	// UnknownSeverity is either a security problem that has not been assigned to
	// a priority yet or a priority that our system did not recognize.
	UnknownSeverity = "Unknown"

	// NegligibleSeverity is technically a security problem, but is only
	// theoretical in nature, requires a very special situation, has almost no
	// install base, or does no real damage. These tend not to get backport from
	// upstream, and will likely not be included in security updates unless
	// there is an easy fix and some other issue causes an update.
	NegligibleSeverity = "Negligible"

	// LowSeverity is a security problem, but is hard to exploit due to
	// environment, requires a user-assisted attack, a small install base, or
	// does very little damage.  These tend to be included in security updates
	// only when higher priority issues require an update, or if many low
	// priority issues have built up.
	LowSeverity = "Low"

	// MediumSeverity is a real security problem, and is exploitable for many
	// people.  Includes network daemon denial of service attacks, cross-site
	// scripting, and gaining user privileges.  Updates should be made soon for
	// this priority of issue.
	MediumSeverity = "Medium"

	// HighSeverity is a real problem, exploitable for many people in a default
	// installation. Includes serious remote denial of services, local root
	// privilege escalations, or data loss.
	HighSeverity = "High"

	// CriticalSeverity is a world-burning problem, exploitable for nearly all
	// people in a default installation of Linux. Includes remote root privilege
	// escalations, or massive data loss.
	CriticalSeverity = "Critical"

	// Defcon1Severity is a Critical problem which has been manually highlighted
	// by the team. It requires an immediate attention.
	Defcon1Severity = "Defcon1"
)

// Severities lists all known severities, ordered from lowest to highest.
var Severities = []string{
	UnknownSeverity,
	NegligibleSeverity,
	LowSeverity,
	MediumSeverity,
	HighSeverity,
	CriticalSeverity,
	Defcon1Severity,
}

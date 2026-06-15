package db

import (
	"errors"

	"github.com/lib/pq"
)

// IsRetryableError reports whether err is a transient PostgreSQL error that is
// safe to retry by re-running the whole transaction. These are the standard
// concurrency-failure classes: deadlock_detected (40P01) and
// serialization_failure (40001). They occur when concurrent writers (for
// example a per-source CVE import racing the background security recalculation)
// touch overlapping rows; the loser is aborted and the operation can simply be
// retried once the contention clears.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "40P01", // deadlock_detected
			"40001": // serialization_failure
			return true
		}
	}
	return false
}

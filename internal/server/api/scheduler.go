package api

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

type cronSchedule struct {
	minute     fieldMatcher
	hour       fieldMatcher
	dayOfMonth fieldMatcher
	month      fieldMatcher
	dayOfWeek  fieldMatcher
}

type fieldMatcher struct {
	values map[int]bool
	any    bool
}

func parseCronField(field string, min, max int) (fieldMatcher, error) {
	f := fieldMatcher{values: map[int]bool{}}
	if field == "*" {
		f.any = true
		return f, nil
	}
	parts := strings.Split(field, "/")
	base := parts[0]
	step := 1
	if len(parts) == 2 {
		s, err := strconv.Atoi(parts[1])
		if err != nil || s <= 0 {
			return f, fmt.Errorf("invalid step: %s", parts[1])
		}
		step = s
	} else if len(parts) > 2 {
		return f, fmt.Errorf("invalid field: %s", field)
	}
	var values []int
	if base == "*" {
		for i := min; i <= max; i++ {
			values = append(values, i)
		}
	} else {
		for _, part := range strings.Split(base, ",") {
			if strings.Contains(part, "-") {
				rng := strings.SplitN(part, "-", 2)
				lo, err1 := strconv.Atoi(rng[0])
				hi, err2 := strconv.Atoi(rng[1])
				if err1 != nil || err2 != nil || lo < min || hi > max || lo > hi {
					return f, fmt.Errorf("invalid range: %s", part)
				}
				for i := lo; i <= hi; i++ {
					values = append(values, i)
				}
			} else {
				v, err := strconv.Atoi(part)
				if err != nil || v < min || v > max {
					return f, fmt.Errorf("invalid value: %s", part)
				}
				values = append(values, v)
			}
		}
	}
	for i := 0; i < len(values); i += step {
		f.values[values[i]] = true
	}
	if len(f.values) == 0 {
		f.any = true
	}
	return f, nil
}

func parseCron(expr string) (cronSchedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return cronSchedule{}, fmt.Errorf("cron expression must have 5 fields, got %d", len(fields))
	}
	var s cronSchedule
	var err error
	s.minute, err = parseCronField(fields[0], 0, 59)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("minute: %w", err)
	}
	s.hour, err = parseCronField(fields[1], 0, 23)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("hour: %w", err)
	}
	s.dayOfMonth, err = parseCronField(fields[2], 1, 31)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("day of month: %w", err)
	}
	s.month, err = parseCronField(fields[3], 1, 12)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("month: %w", err)
	}
	s.dayOfWeek, err = parseCronField(fields[4], 0, 6)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("day of week: %w", err)
	}
	return s, nil
}

func (m fieldMatcher) matches(v int) bool {
	return m.any || m.values[v]
}

func nextCronTime(schedule cronSchedule, after time.Time) time.Time {
	t := after.Add(time.Minute).Truncate(time.Minute)
	maxIter := 525960 // ~1 year of minutes
	for i := 0; i < maxIter; i++ {
		if schedule.month.matches(int(t.Month())) &&
			schedule.dayOfMonth.matches(t.Day()) &&
			schedule.dayOfWeek.matches(int(t.Weekday())) &&
			schedule.hour.matches(t.Hour()) &&
			schedule.minute.matches(t.Minute()) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}

func computeNextRun(expr string, now time.Time) (time.Time, error) {
	schedule, err := parseCron(expr)
	if err != nil {
		return time.Time{}, err
	}
	next := nextCronTime(schedule, now)
	if next.IsZero() {
		return time.Time{}, fmt.Errorf("no matching time found within 1 year for: %s", expr)
	}
	return next, nil
}

func (s *Server) startScheduler() {
	if envBool("BONGSU_SCHEDULER_DISABLED", false) {
		log.Println("Scan scheduler disabled")
		return
	}
	interval := time.Duration(envInt("BONGSU_SCHEDULER_INTERVAL_SECONDS", 60)) * time.Second
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	go func() {
		for {
			time.Sleep(interval + time.Duration(rand.Intn(5000))*time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			s.runSchedulerTick(ctx, time.Now())
			cancel()
		}
	}()
	log.Printf("Scan scheduler started (interval: %s)", interval)
}

func (s *Server) runSchedulerTick(ctx context.Context, now time.Time) {
	due, err := s.db.GetDueScheduledScans(ctx, now)
	if err != nil {
		log.Printf("scheduler tick error: %v", err)
		return
	}
	for _, schedule := range due {
		hostIDs, err := s.expandHostFilter(ctx, schedule.HostFilter)
		if err != nil {
			log.Printf("scheduler host filter error for %s: %v", schedule.ID, err)
			continue
		}
		queued := 0
		for _, hostID := range hostIDs {
			req := &models.ScanRequest{
				HostID:       hostID,
				ScanType:     schedule.ScanType,
				PackagesOnly: schedule.PackagesOnly,
				Reason:       fmt.Sprintf("scheduled: %s", schedule.Name),
			}
			if err := s.db.CreateScanRequest(ctx, req); err != nil {
				log.Printf("scheduler create scan request for host %s: %v", hostID, err)
				continue
			}
			queued++
		}
		nextRun, err := computeNextRun(schedule.CronExpr, now)
		if err != nil {
			log.Printf("scheduler compute next run for %s: %v", schedule.ID, err)
			nextRun = now.Add(time.Hour)
		}
		if err := s.db.UpdateScheduledScanRunTimes(ctx, schedule.ID, now, nextRun); err != nil {
			log.Printf("scheduler update run times for %s: %v", schedule.ID, err)
		}
		if queued > 0 {
			log.Printf("scheduler %q: queued %d scans, next run at %s", schedule.Name, queued, nextRun.Format(time.RFC3339))
		}
	}
}

func (s *Server) expandHostFilter(ctx context.Context, hostFilter string) ([]string, error) {
	if hostFilter == "" {
		hosts, err := s.db.ListHosts(ctx)
		if err != nil {
			return nil, err
		}
		ids := make([]string, len(hosts))
		for i, h := range hosts {
			ids[i] = h.ID
		}
		return ids, nil
	}
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	filters := strings.Split(hostFilter, ",")
	filterMap := map[string]bool{}
	for _, f := range filters {
		f = strings.TrimSpace(f)
		if f != "" {
			filterMap[f] = true
		}
	}
	var ids []string
	for _, h := range hosts {
		if filterMap[h.ID] || filterMap[h.Hostname] {
			ids = append(ids, h.ID)
		}
	}
	return ids, nil
}

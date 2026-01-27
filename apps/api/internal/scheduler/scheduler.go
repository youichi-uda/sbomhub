package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Job represents a scheduled job
type Job struct {
	Name     string
	Schedule string // cron expression
	Handler  func(ctx context.Context) error
	running  bool
	mu       sync.Mutex
}

// Scheduler manages scheduled jobs
type Scheduler struct {
	jobs    []*Job
	ticker  *time.Ticker
	done    chan bool
	running bool
	mu      sync.Mutex
}

// New creates a new scheduler
func New() *Scheduler {
	return &Scheduler{
		jobs: make([]*Job, 0),
		done: make(chan bool),
	}
}

// AddJob adds a job to the scheduler
func (s *Scheduler) AddJob(name, schedule string, handler func(ctx context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.jobs = append(s.jobs, &Job{
		Name:     name,
		Schedule: schedule,
		Handler:  handler,
	})

	slog.Info("job registered", "name", name, "schedule", schedule)
}

// Start starts the scheduler
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	// Check every minute
	s.ticker = time.NewTicker(1 * time.Minute)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.checkAndRunJobs()
			case <-s.done:
				return
			}
		}
	}()

	slog.Info("scheduler started", "jobs", len(s.jobs))
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	s.ticker.Stop()
	close(s.done)

	slog.Info("scheduler stopped")
}

func (s *Scheduler) checkAndRunJobs() {
	now := time.Now()

	for _, job := range s.jobs {
		if shouldRun(job.Schedule, now) {
			go s.runJob(job)
		}
	}
}

func (s *Scheduler) runJob(job *Job) {
	job.mu.Lock()
	if job.running {
		job.mu.Unlock()
		slog.Debug("job already running", "name", job.Name)
		return
	}
	job.running = true
	job.mu.Unlock()

	defer func() {
		job.mu.Lock()
		job.running = false
		job.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	slog.Info("job started", "name", job.Name)
	start := time.Now()

	if err := job.Handler(ctx); err != nil {
		slog.Error("job failed", "name", job.Name, "error", err, "duration", time.Since(start))
		return
	}

	slog.Info("job completed", "name", job.Name, "duration", time.Since(start))
}

// shouldRun checks if a job should run based on its schedule
// Simplified cron-like parsing: "minute hour * * *"
func shouldRun(schedule string, now time.Time) bool {
	// Parse schedule (simplified)
	// Format: "0 6 * * *" = daily at 6:00
	// Format: "0 * * * *" = hourly at :00
	// Format: "0 6 * * 1" = every Monday at 6:00

	var minute, hour int
	var dayOfWeek = -1

	// Parse common formats
	switch schedule {
	case "hourly":
		return now.Minute() == 0
	case "daily":
		return now.Hour() == 6 && now.Minute() == 0
	default:
		// Try to parse cron-like format
		n, _ := parseSchedule(schedule, &minute, &hour, &dayOfWeek)
		if n < 2 {
			return false
		}

		if now.Minute() != minute {
			return false
		}
		if now.Hour() != hour {
			return false
		}
		if dayOfWeek >= 0 && int(now.Weekday()) != dayOfWeek {
			return false
		}
		return true
	}
}

func parseSchedule(schedule string, minute, hour, dayOfWeek *int) (int, error) {
	var day, month, dow string
	n, _ := sscanf(schedule, "%d %d %s %s %s", minute, hour, &day, &month, &dow)
	if dow != "" && dow != "*" {
		*dayOfWeek = parseInt(dow)
	}
	return n, nil
}

func sscanf(s string, format string, args ...interface{}) (int, error) {
	// Simplified scanf implementation
	var count int
	parts := splitWhitespace(s)
	
	for i, arg := range args {
		if i >= len(parts) {
			break
		}
		switch v := arg.(type) {
		case *int:
			*v = parseInt(parts[i])
			count++
		case *string:
			*v = parts[i]
			count++
		}
	}
	return count, nil
}

func splitWhitespace(s string) []string {
	result := []string{}
	current := ""
	for _, c := range s {
		if c == ' ' || c == '\t' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func parseInt(s string) int {
	var result int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		}
	}
	return result
}

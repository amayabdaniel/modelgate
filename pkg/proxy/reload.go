package proxy

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
	"github.com/amayabdaniel/modelgate/pkg/security"
	"gopkg.in/yaml.v3"
)

// PolicyReloader watches a policy file and reloads the middleware checker on changes.
type PolicyReloader struct {
	mu         sync.RWMutex
	filePath   string
	lastModTime time.Time
	lastSize   int64
	middleware *Middleware
	interval   time.Duration
	stopCh     chan struct{}
	reloadCount int
}

// NewPolicyReloader creates a reloader that watches the given file.
func NewPolicyReloader(filePath string, middleware *Middleware, interval time.Duration) *PolicyReloader {
	return &PolicyReloader{
		filePath:   filePath,
		middleware: middleware,
		interval:   interval,
		stopCh:     make(chan struct{}),
	}
}

// Start begins watching the policy file in a goroutine.
func (pr *PolicyReloader) Start() {
	go pr.watchLoop()
	log.Printf("modelgate: policy reloader watching %s every %s", pr.filePath, pr.interval)
}

// Stop halts the watcher.
func (pr *PolicyReloader) Stop() {
	close(pr.stopCh)
}

// ReloadCount returns how many successful reloads have occurred.
func (pr *PolicyReloader) ReloadCount() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.reloadCount
}

func (pr *PolicyReloader) watchLoop() {
	ticker := time.NewTicker(pr.interval)
	defer ticker.Stop()

	for {
		select {
		case <-pr.stopCh:
			return
		case <-ticker.C:
			if err := pr.checkAndReload(); err != nil {
				log.Printf("modelgate: reload error: %v", err)
			}
		}
	}
}

func (pr *PolicyReloader) checkAndReload() error {
	info, err := os.Stat(pr.filePath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", pr.filePath, err)
	}

	pr.mu.RLock()
	changed := info.ModTime() != pr.lastModTime || info.Size() != pr.lastSize
	pr.mu.RUnlock()

	if !changed {
		return nil
	}

	// File changed — reload
	data, err := os.ReadFile(pr.filePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", pr.filePath, err)
	}

	var policy v1alpha1.InferencePolicySpec
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("parsing %s: %w", pr.filePath, err)
	}

	if err := policy.Validate(); err != nil {
		return fmt.Errorf("validating %s: %w", pr.filePath, err)
	}

	checker, err := security.NewPromptChecker(policy.Security)
	if err != nil {
		return fmt.Errorf("creating checker: %w", err)
	}

	// Swap the checker in the middleware
	pr.middleware.mu.Lock()
	pr.middleware.checker = checker
	pr.middleware.policy = policy
	pr.middleware.mu.Unlock()

	pr.mu.Lock()
	pr.lastModTime = info.ModTime()
	pr.lastSize = info.Size()
	pr.reloadCount++
	pr.mu.Unlock()

	log.Printf("modelgate: policy reloaded from %s (reload #%d)", pr.filePath, pr.reloadCount)
	return nil
}

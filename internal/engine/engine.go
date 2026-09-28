// Package engine implements a small, data-driven fingerprint engine.
// Protocol knowledge lives in JSON rule files, not in Go switch statements.
package engine

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"bannerfp/internal/model"
)

// Rule is one external JSON rule. Named capture groups control field
// extraction: product, version and os. A static product field wins over a
// captured product value.
type Rule struct {
	ID         string   `json:"id"`
	Protocol   string   `json:"protocol"`
	Product    string   `json:"product"`
	Pattern    string   `json:"pattern"`
	Patterns   []string `json:"patterns"`
	Priority   int      `json:"priority"`
	Confidence float64  `json:"confidence"`
	Ports      []int    `json:"ports"`
}

type ruleFile struct {
	Rules []Rule `json:"rules"`
}

type compiledRule struct {
	rule    Rule
	regexps []*regexp.Regexp
}

// Engine holds compiled rules ordered by descending priority. Rule order in
// the files is preserved for equal priorities.
type Engine struct {
	rules  []compiledRule
	logger *slog.Logger
}

// LoadDir loads all *.json rule files from dir. Both {"rules":[...]} and a
// top-level array are accepted.
func LoadDir(dir string, logger *slog.Logger) (*Engine, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}

	var rules []Rule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		var rf ruleFile
		if err := json.Unmarshal(data, &rf); err != nil || len(rf.Rules) == 0 {
			var arr []Rule
			if err2 := json.Unmarshal(data, &arr); err2 != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			rf.Rules = arr
		}
		for _, rule := range rf.Rules {
			if err := validateRule(rule); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			rules = append(rules, rule)
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules loaded from %s", dir)
	}

	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		cr := compiledRule{rule: rule}
		patterns := append([]string{}, rule.Patterns...)
		if rule.Pattern != "" {
			patterns = append([]string{rule.Pattern}, patterns...)
		}
		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s: compile %q: %w", rule.ID, pattern, err)
			}
			cr.regexps = append(cr.regexps, re)
		}
		compiled = append(compiled, cr)
	}

	return &Engine{rules: compiled, logger: logger}, nil
}

func validateRule(rule Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule id is empty")
	}
	if rule.Protocol == "" {
		return fmt.Errorf("rule %s: protocol is empty", rule.ID)
	}
	if rule.Pattern == "" && len(rule.Patterns) == 0 {
		return fmt.Errorf("rule %s: no pattern", rule.ID)
	}
	if rule.Confidence <= 0 || rule.Confidence > 1 {
		return fmt.Errorf("rule %s: confidence must be in (0,1]", rule.ID)
	}
	return nil
}

// RulesCount returns the number of loaded rules.
func (e *Engine) RulesCount() int { return len(e.rules) }

// Fingerprint identifies one banner. It never panics: a rule failure is
// converted to an unknown result so a bad batch item cannot take down the API.
func (e *Engine) Fingerprint(item model.Item) (res model.Result) {
	res = model.Result{IP: item.IP, Port: item.Port, Protocol: "unknown"}
	defer func() {
		if rec := recover(); rec != nil {
			if e.logger != nil {
				e.logger.Error("rule match panic", "err", rec, "ip", item.IP, "port", item.Port)
			}
			res = model.Result{IP: item.IP, Port: item.Port, Protocol: "unknown"}
		}
	}()

	type candidate struct {
		cr    *compiledRule
		re    *regexp.Regexp
		subs  []string
		score int
	}

	var best *candidate
	for i := range e.rules {
		cr := &e.rules[i]
		for _, re := range cr.regexps {
			subs := re.FindStringSubmatch(item.Banner)
			if subs == nil {
				continue
			}
			score := cr.rule.Priority * 2
			if containsInt(cr.rule.Ports, item.Port) {
				score++
			}
			if best == nil || score > best.score {
				best = &candidate{cr: cr, re: re, subs: subs, score: score}
			}
			break
		}
	}
	if best == nil {
		return res
	}

	res.Protocol = best.cr.rule.Protocol
	res.Product = best.cr.rule.Product
	res.Confidence = best.cr.rule.Confidence
	names := best.re.SubexpNames()
	for i, name := range names {
		if i == 0 || name == "" || i >= len(best.subs) {
			continue
		}
		value := strings.TrimSpace(best.subs[i])
		if value == "" {
			continue
		}
		switch name {
		case "product":
			if res.Product == "" {
				res.Product = value
			}
		case "version":
			res.Version = value
		case "os":
			res.OSHint = value
		}
	}
	if res.Confidence > 0.99 {
		res.Confidence = 0.99
	}
	return res
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

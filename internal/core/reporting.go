package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"
)

type Report struct {
	CaseID    string
	Timestamp time.Time
	Threats   []Threat
	Stats     map[string]int
}

func GenerateReport(caseID string, threats []Threat) error {
	report := Report{
		CaseID:    caseID,
		Timestamp: time.Now(),
		Threats:   threats,
		Stats:     make(map[string]int),
	}

	for range threats {
		// report.Stats[t.Name]++ // simple count
	}

	// CSV/JSON Output
	data, _ := json.MarshalIndent(report, "", "  ")
	filename := fmt.Sprintf("report_%s.json", caseID)

	err := ioutil.WriteFile(filename, data, 0644)
	if err == nil {
		fmt.Printf("[REPORT] Generated %s\n", filename)
	}

	// Create HTML (Simplistic)
	html := fmt.Sprintf("<h1>Arakne Scan Report</h1><p>Case: %s</p><ul>", caseID)
	for _, t := range threats {
		html += fmt.Sprintf("<li><b>%s</b>: %s (Level %d)</li>", t.Name, t.Description, t.Level)
	}
	html += "</ul>"
	ioutil.WriteFile(fmt.Sprintf("report_%s.html", caseID), []byte(html), 0644)

	return err
}

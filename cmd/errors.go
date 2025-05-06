package cmd

import (
	"fmt"
	"os"
	"strings"
)

type ValidationError struct {
	Sections map[string]*ValidationSection
	ExitCode int
}

type ValidationSection struct {
	Issues        []string
	Solutions     []string
	SettingAdvice []string
}

func (e ValidationError) Error() string {
	var sb strings.Builder
	sb.WriteString("🔴 Configuration Errors\n")
	sb.WriteString("══════════════════════\n\n")

	for sectionName, section := range e.Sections {
		if len(section.Issues) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("■ %s\n", sectionName))
		sb.WriteString(strings.Repeat("─", len(sectionName)+2) + "\n")
		sb.WriteString("  Issue(s):\n")

		for _, item := range section.Issues {
			sb.WriteString(fmt.Sprintf("    • %s\n", item))
		}

		if len(section.Solutions) > 0 {
			sb.WriteString("\n  How to fix:\n")
			for _, solution := range section.Solutions {
				sb.WriteString(fmt.Sprintf("    • %s\n", solution))
			}
		}

		if len(section.SettingAdvice) > 0 {
			sb.WriteString("\n  Ways to provide values:\n")
			for _, advice := range section.SettingAdvice {
				sb.WriteString(fmt.Sprintf("    • %s\n", advice))
			}
		}

		sb.WriteString("\n")
	}

	sb.WriteString("══════════════════════\n")
	return sb.String()
}

func (e ValidationError) Exit() {
	fmt.Println(e.Error())
	os.Exit(e.ExitCode)
}

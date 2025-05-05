package cmd

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func executeCommand(root *cobra.Command, args ...string) (output string, err error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	cfgFile = filepath.Join(os.TempDir(), "nonexistent-dir", "nonexistent.yaml")

	err = root.Execute()

	return buf.String(), err
}

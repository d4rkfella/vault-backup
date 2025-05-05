package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/d4rkfella/vault-backup/cmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	cmd.ExecuteContext(ctx)
}

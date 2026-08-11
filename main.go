// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/DataDog/scfw/scfw/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := cli.RootCmd().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

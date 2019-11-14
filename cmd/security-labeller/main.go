package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/quay/container-security-operator/labeller"

	log "github.com/go-kit/kit/log"
	corev1 "k8s.io/api/core/v1"
)

type arrayFlags []string

func (flags *arrayFlags) String() string {
	return strings.Join(*flags, ",")
}

func (flags *arrayFlags) Set(value string) error {
	*flags = strings.Split(value, ",")
	return nil
}

func waitForSignals(signals ...os.Signal) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, signals...)
	<-interrupts
}

func main() {
	// Parse cmd line arguments
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var namespaces arrayFlags
	flag.Var(&namespaces, "namespaces", "Namespaces to scan, separated by commas. Leave empty to scan all namespaces.")
	flagConfigPath := flag.String("config", "", "Load configuration from file.")
	promAddr := flag.String("promAddr", ":8081", "Prometheus metrics endpoint.")
	resyncInterval := flag.String("resyncInterval", "30m", "Controller resync interval.")
	labelPrefix := flag.String("labelPrefix", "secscan", "CR label prefix.")
	scannerHost := flag.String("scannerHost", "https://quay.io", "Scanner endpoint.")
	scannerToken := flag.String("scannerToken", "", "Scanner bearer token.")
	scannerVersion := flag.Int("scannerVersion", 1, "Scanner api version.")
	scannerType := flag.String("scannerType", "quay", "Scanner type.")
	wellknownEndpoint := flag.String("wellknownEndpoint", ".well-known/app-capabilities", "Wellknown endpoint")

	flagKubeConfigPath := flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	flag.Parse()

	// Load labeller config from file OR command line args
	var (
		cfg *labeller.Config
		err error
	)
	interval, err := time.ParseDuration(*resyncInterval)
	if *flagConfigPath != "" {
		cfg, err = labeller.LoadConfig(*flagConfigPath)
		if err != nil {
			panic(err)
		}
	} else {
		if len(namespaces) == 1 && namespaces[0] == corev1.NamespaceAll {
			namespaces = []string{}
		}
		cfg = &labeller.Config{
			Namespaces:        namespaces,
			Interval:          interval,
			LabelPrefix:       *labelPrefix,
			PrometheusAddr:    *promAddr,
			WellknownEndpoint: *wellknownEndpoint,
			SecurityScanner: labeller.SecurityScannerOptions{
				*scannerHost,
				*scannerToken,
				*scannerVersion,
				*scannerType,
			},
		}
	}

	// Create new Labeller instance
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	l, err := labeller.New(cfg, *flagKubeConfigPath, logger)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start Labeller
	l.Run(ctx.Done())

	// Wait for interrupt
	waitForSignals(syscall.SIGINT, syscall.SIGTERM)
	cancel()
}

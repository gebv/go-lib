package test

import (
	"context"
	"flag"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var Ctx context.Context

func TestMain(m *testing.M) {
	rand.Seed(time.Now().UnixNano())

	log.SetPrefix("testmain: ")
	log.SetFlags(0)

	flag.Parse()

	if testing.Short() {
		log.Print("-short flag is passed, skipping integration tests.")
		os.Exit(0)
	}

	log.Println("Start TestMain.")
	log.Println("Use SKIP_TLSVERIFY_INFRA env for skip install infra for tls/verify tests.")

	var cancel context.CancelFunc
	Ctx, cancel = context.WithCancel(context.Background())

	// handle termination signals: first one cancels context, force exit on the second one
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGTERM, unix.SIGINT)
	go func() {
		s := <-signals
		log.Printf("Got %s, shutting down...", unix.SignalName(s.(unix.Signal)))
		cancel()

		s = <-signals
		log.Panicf("Got %s, exiting!", unix.SignalName(s.(unix.Signal)))
	}()

	var exitCode int
	defer func() {
		if p := recover(); p != nil {
			cancel() // NOTE: для отмены бинарников запущенных (решило проблему зависших процессов в случае паники в тесте?)
			log.Println("stacktrace from panic:", string(debug.Stack()))
		}
		log.Printf("Stoped main_test with exit code %d, sleep 10 sec\n", exitCode)
		time.Sleep(1 * time.Second)
		os.Exit(exitCode)
	}()

	if os.Getenv("SKIP_TLSVERIFY_INFRA") == "" {
		runMake("-C", "./testdata/verify", "gen-trusted-ssl")
		runMake("-C", "./testdata/verify", "run-servers")
	} else {
		log.Println("Skipted installing infrastructure for tls/verify tests.")
	}

	log.Println("running tests")
	exitCode = m.Run()
	log.Println("tests completed - canceling the main context")
	cancel()
	log.Println("bye bye.")
}

func runMake(args ...string) {
	cmd := exec.Command("make", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Print("runMake: run make with args:", strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		log.Panic("runMake: failed run make task, with error:", err)
	}
}

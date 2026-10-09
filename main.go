package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	requiredChainID = 31337
	anvilReadyMax   = 30 * time.Second
	anvilPollEvery  = 250 * time.Millisecond
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("scanner", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		rpcURL    = fs.String("rpc", "", "pre-running RPC URL; skips Anvil spawn")
		forkURL   = fs.String("fork-url", "", "Base RPC URL to fork (required unless --rpc)")
		forkBlock = fs.Uint64("fork-block", 0, "pinned fork block number (required unless --rpc)")
		anvilBin  = fs.String("anvil", "anvil", "path to anvil binary")
		anvilPort = fs.Int("anvil-port", 8545, "anvil listen port")
		outPath   = fs.String("out", "", "output file (default stdout)")
		format    = fs.String("format", "text", "output format: text | json")
		timeout   = fs.Duration("timeout", 15*time.Minute, "pipeline timeout")
	)

	opsF := registerOpsFlags(fs)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "scanner: signal received, shutting down")
		cancelRoot()
	}()

	// ---------- Anvil lifecycle ----------

	var anvil *exec.Cmd

	effectiveRPC := *rpcURL
	if effectiveRPC == "" {
		if *forkURL == "" || *forkBlock == 0 {
			fmt.Fprintln(os.Stderr, "scanner: --fork-url and --fork-block are required unless --rpc is set")
			return 1
		}

		anvil = exec.Command(*anvilBin,
			"--fork-url", *forkURL,
			"--fork-block-number", fmt.Sprintf("%d", *forkBlock),
			"--port", fmt.Sprintf("%d", *anvilPort),
			"--chain-id", fmt.Sprintf("%d", requiredChainID),
		)
		anvil.Stdout = os.Stderr
		anvil.Stderr = os.Stderr

		if err := anvil.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "scanner: anvil start: %v\n", err)
			return 1
		}
		defer func() {
			if anvil.Process == nil {
				return
			}
			_ = anvil.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = anvil.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = anvil.Process.Kill()
			}
		}()

		effectiveRPC = fmt.Sprintf("http://127.0.0.1:%d", *anvilPort)
	}

	// ---------- Connect ----------

	setupCtx, cancelSetup := context.WithTimeout(rootCtx, anvilReadyMax)
	defer cancelSetup()

	rpcClient, err := dialReady(setupCtx, effectiveRPC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: rpc connect: %v\n", err)
		return 1
	}
	defer rpcClient.Close()

	client := ethclient.NewClient(rpcClient)

	// ---------- Chain-ID guard ----------

	chainID, err := client.ChainID(setupCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: chain-id read: %v\n", err)
		return 1
	}
	if chainID.Int64() != requiredChainID {
		fmt.Fprintf(os.Stderr, "scanner: chain-id guard failed: got %d, want %d\n",
			chainID.Int64(), requiredChainID)
		return 1
	}

	// ---------- Pipeline ----------

	runCtx, cancelRun := context.WithTimeout(rootCtx, *timeout)
	defer cancelRun()

	blockNum, err := client.BlockNumber(runCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: block number: %v\n", err)
		return 2
	}

	log.Printf("scanner: forked at block %d, chain %d", blockNum, chainID.Int64())

	// Stage 1: inventory.
	markets, err := Discover(runCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: discovery: %v\n", err)
		return 2
	}
	log.Printf("scanner: %d markets from API", len(markets))

	uniqueCollaterals := len(UniqueCollaterals(markets))
	uniqueOracles := len(UniqueOracles(markets))
	log.Printf("scanner: %d unique collateral assets, %d unique oracles",
		uniqueCollaterals, uniqueOracles)

	// Stage 2: trace-based oracle triage.
	shortlist := TriageOracles(runCtx, client, rpcClient, markets)
	log.Printf("scanner: %d shortlisted markets", len(shortlist))

	// Stage 3: fork confirmation.
	confirmed, suspected := Simulate(runCtx, client, rpcClient, shortlist)
	log.Printf("scanner: %d confirmed, %d suspected", len(confirmed), len(suspected))

	meta := RunMetadata{
		ChainID:            chainID.Int64(),
		BlockNumber:        blockNum,
		MarketsFromAPI:     len(markets),
		SuspiciousOracles:  len(markets),
		UniqueOracles:      uniqueOracles,
		MarketsShortlisted: len(shortlist),
		ConfirmedCount:     len(confirmed),
		SuspectedCount:     len(suspected),
	}
	ops := DefaultOperationalProperties(opsF.toPresent())

	rep, err := BuildReport(runCtx, client, meta, confirmed, suspected, ops)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: build report: %v\n", err)
		return 2
	}

	return WriteReport(*outPath, *format, rep)
}

// ---------- RPC readiness ----------

func dialReady(ctx context.Context, url string) (*rpc.Client, error) {
	var lastErr error
	ticker := time.NewTicker(anvilPollEvery)
	defer ticker.Stop()

	for {
		c, err := rpc.DialContext(ctx, url)
		if err == nil {
			var id string
			callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			callErr := c.CallContext(callCtx, &id, "eth_chainId")
			cancel()
			if callErr == nil {
				return c, nil
			}
			lastErr = callErr
			c.Close()
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return nil, fmt.Errorf("%w (last: %v)", ctx.Err(), lastErr)
			}
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

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

	"github.com/ethereum/go-ethereum/common"
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
	// ---------- Flags ----------

	fs := flag.NewFlagSet("scanner", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		rpcURL       = fs.String("rpc", "", "pre-running RPC URL; skips Anvil spawn")
		forkURL      = fs.String("fork-url", "", "Base RPC URL to fork (required unless --rpc)")
		forkBlock    = fs.Uint64("fork-block", 0, "pinned fork block number (required unless --rpc)")
		anvilBin     = fs.String("anvil", "anvil", "path to anvil binary")
		anvilPort    = fs.Int("anvil-port", 8545, "anvil listen port")
		outPath      = fs.String("out", "", "output file (default stdout)")
		format       = fs.String("format", "text", "output format: text | json")
		timeout      = fs.Duration("timeout", 15*time.Minute, "pipeline timeout")
	)

	opsF := registerOpsFlags(fs)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}

	// ---------- Signal handling ----------

	// Root context cancelled on SIGINT/SIGTERM. Anvil teardown runs on
	// the way out regardless.
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
		// Defer teardown: kill, then wait so we do not leak a zombie.
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

	// Confirm the two hardcoded protocol addresses are populated.
	if (MorphoBlueAddress == common.Address{}) && (AaveV3PoolAddress == common.Address{}) {
		fmt.Fprintln(os.Stderr, "scanner: config: MorphoBlueAddress and AaveV3PoolAddress are both unset; fill in config.go")
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

	candidates, err := Discover(runCtx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: discovery: %v\n", err)
		return 2
	}
	log.Printf("scanner: %d candidates after EOA filter", len(candidates))

	suspected := AnalyzeCandidates(runCtx, client, candidates)
	log.Printf("scanner: %d SPOT_DEPENDENT (suspected)", len(suspected))

	confirmed := Simulate(runCtx, client, rpcClient, suspected)
	log.Printf("scanner: %d confirmed via simulation", len(confirmed))

	meta := RunMetadata{
		ChainID:        chainID.Int64(),
		BlockNumber:    blockNum,
		CandidateCount: len(candidates),
		FalsePositives: len(suspected) - len(confirmed),
	}

	ops := DefaultOperationalProperties(opsF.toPresent())

	rep, err := BuildReport(runCtx, client, meta, confirmed, ops)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: build report: %v\n", err)
		return 2
	}

	return WriteReport(*outPath, *format, rep)
}

// ---------- RPC readiness ----------

// dialReady polls until the endpoint answers eth_chainId and reports
// the required chain, or until ctx expires. Anvil takes a variable
// amount of time to fork depending on the upstream RPC.
func dialReady(ctx context.Context, url string) (*rpc.Client, error) {
	var lastErr error
	ticker := time.NewTicker(anvilPollEvery)
	defer ticker.Stop()

	for {
		// Try immediately on first iteration, then after each tick.
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

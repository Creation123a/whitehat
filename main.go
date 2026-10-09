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
	anvilReadyMax   = 60 * time.Second
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
		timeout   = fs.Duration("timeout", 20*time.Minute, "pipeline timeout")
		minProt   = fs.Int("min-protocols", MinProtocolsPerMarket,
			"minimum protocols attached to a market for it to be scanned")
		minTVL = fs.Float64("min-tvl", MinProtocolTVLUSD,
			"minimum protocol TVL (USD) to survive dust filter")
	)

	_ = registerOpsFlags(fs)

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

	var anvil *exec.Cmd
	effectiveRPC := *rpcURL
	if effectiveRPC == "" {
		if *forkURL == "" || *forkBlock == 0 {
			fmt.Fprintln(os.Stderr, "scanner: --fork-url and --fork-block required unless --rpc is set")
			return 1
		}
		anvil = exec.Command(*anvilBin,
			"--fork-url", *forkURL,
			"--fork-block-number", fmt.Sprintf("%d", *forkBlock),
			"--port", fmt.Sprintf("%d", *anvilPort),
			"--chain-id", fmt.Sprintf("%d", requiredChainID),
			"--fork-retry-backoff", "2000",
			"--retries", "10",
			"--timeout", "60000",
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

	setupCtx, cancelSetup := context.WithTimeout(rootCtx, anvilReadyMax)
	defer cancelSetup()

	rpcClient, err := dialReady(setupCtx, effectiveRPC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: rpc connect: %v\n", err)
		return 1
	}
	defer rpcClient.Close()

	client := ethclient.NewClient(rpcClient)

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

	runCtx, cancelRun := context.WithTimeout(rootCtx, *timeout)
	defer cancelRun()

	blockNum, err := client.BlockNumber(runCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: block number: %v\n", err)
		return 2
	}
	log.Printf("scanner: forked at block %d, chain %d", blockNum, chainID.Int64())

	// ---- Stage 1: market discovery ----
	markets, err := DiscoverMarkets(runCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: market discovery: %v\n", err)
		return 2
	}
	log.Printf("scanner: %d markets from Morpho API", len(markets))

	// ---- Stage 2: protocol discovery ----
	protocols, err := DiscoverProtocols(runCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: protocol discovery: %v\n", err)
		return 2
	}
	log.Printf("scanner: %d protocols from vaults API", len(protocols))

	// ---- Stage 3: attach protocols to markets ----
	indexed := BuildMarketProtocolIndex(markets, protocols)
	log.Printf("scanner: %d markets have at least one protocol attached", len(indexed))

	// ---- Stage 4: filter markets by protocol count ----
	afterCount := FilterMarketsByProtocolCount(indexed, *minProt)
	log.Printf("scanner: %d markets after min-protocols=%d filter",
		len(afterCount), *minProt)

	// ---- Stage 5: dust filter on protocols ----
	afterTVL := FilterProtocolsByTVL(afterCount, *minTVL)
	log.Printf("scanner: %d markets after TVL filter (min=$%.0f)",
		len(afterTVL), *minTVL)

	if len(afterTVL) == 0 {
		log.Printf("scanner: no markets survived the filters; nothing to scan")
		writeEmptyReport(*outPath, *format, blockNum, chainID.Int64(),
			len(markets), len(protocols), len(indexed))
		return 0
	}

	// ---- Stage 6: oracle triage (spot AMM check) ----
	flatMarkets := make([]MorphoMarket, 0, len(afterTVL))
	for _, mp := range afterTVL {
		flatMarkets = append(flatMarkets, mp.Market)
	}
	verdicts, triageStats := TriageOracles(runCtx, client, rpcClient, flatMarkets)
	log.Printf("scanner[triage]: oracles=%d ok=%d reverted=%d error=%d shortlisted=%d",
		triageStats.Total, triageStats.TraceOK,
		triageStats.TraceReverted, triageStats.TraceError,
		triageStats.Shortlisted)

	// Attach traced pool + selectors back to markets in the joined list.
	for i := range afterTVL {
		v, ok := verdicts[afterTVL[i].Market.MarketID]
		if !ok {
			continue
		}
		afterTVL[i].Market.Selectors = v.Selectors
		afterTVL[i].Market.TracedPools = v.Pools
	}

	// ---- Stage 7: keep only vulnerable markets ----
	vulnSet := make(map[string]bool, len(verdicts))
	for id := range verdicts {
		vulnSet[id] = true
	}
	vulnerable := FilterMarketsByOracleVulnerability(afterTVL, vulnSet)
	log.Printf("scanner: %d vulnerable markets after oracle filter", len(vulnerable))

	// ---- Stage 8: fork confirmation ----
	confirmed, suspected := Simulate(runCtx, client, rpcClient, vulnerable)
	log.Printf("scanner: %d confirmed, %d suspected", len(confirmed), len(suspected))

	meta := RunMetadata{
		ChainID:              chainID.Int64(),
		BlockNumber:          blockNum,
		MarketsFromAPI:       len(markets),
		ProtocolsFromAPI:     len(protocols),
		MarketsAfterCountFlt: len(afterCount),
		MarketsAfterTVLFlt:   len(afterTVL),
		MarketsVulnerable:    len(vulnerable),
		ConfirmedCount:       len(confirmed),
		SuspectedCount:       len(suspected),
	}

	rep, err := BuildReport(runCtx, client, meta, confirmed, suspected)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: build report: %v\n", err)
		return 2
	}
	return WriteReport(*outPath, *format, rep)
}

// writeEmptyReport is called when the filters prune everything.
// The report is still emitted so the run is auditable.
func writeEmptyReport(path, format string, block uint64, chainID int64,
	markets, protocols, indexed int) {

	meta := RunMetadata{
		ChainID:              chainID,
		BlockNumber:          block,
		MarketsFromAPI:       markets,
		ProtocolsFromAPI:     protocols,
		MarketsAfterCountFlt: 0,
		MarketsAfterTVLFlt:   0,
		MarketsVulnerable:    0,
		ConfirmedCount:       0,
		SuspectedCount:       0,
	}
	rep, _ := BuildReport(context.Background(), nil, meta, nil, nil)
	_ = WriteReport(path, format, rep)
}

// dialReady blocks until the RPC answers eth_chainId.
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

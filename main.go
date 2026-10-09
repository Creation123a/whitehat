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
		minProt   = fs.Int("min-protocols", 0,
			"optional post-join filter: drop markets with fewer than N protocols (0 = off)")
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

	// ---- Stage 1: market discovery (Morpho Blue markets) ----
	markets, err := DiscoverMarkets(runCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: market discovery: %v\n", err)
		return 2
	}
	log.Printf("scanner: %d markets from Morpho API", len(markets))

	if len(markets) == 0 {
		log.Printf("scanner: no markets returned from API; nothing to scan")
		writeEmptyReport(*outPath, *format, blockNum, chainID.Int64(), 0, 0, 0)
		return 0
	}

	// ---- Stage 2: oracle triage over ALL markets, BEFORE any
	//      protocol filtering or TVL filtering. ----
	verdicts, triageStats := TriageOracles(runCtx, client, rpcClient, markets)
	log.Printf("scanner[triage]: oracles=%d ok=%d reverted=%d error=%d shortlisted=%d",
		triageStats.Total, triageStats.TraceOK,
		triageStats.TraceReverted, triageStats.TraceError,
		triageStats.Shortlisted)

	// ---- Stage 3: keep only markets whose oracle has a spot-AMM
	//      read anywhere in its pricing path. ----
	var vulnerableMarkets []MorphoMarket
	for _, m := range markets {
		v, ok := verdicts[m.MarketID]
		if !ok || !v.Shortlisted {
			continue
		}
		m.Selectors = v.Selectors
		m.TracedPools = v.Pools
		vulnerableMarkets = append(vulnerableMarkets, m)
	}
	log.Printf("scanner: %d vulnerable markets after oracle triage",
		len(vulnerableMarkets))

	// ---- Stage 4: protocol universe discovery (Morpho vaults
	//      + DefiLlama, with best-effort SQD resolution). ----
	protocols, err := DiscoverAllProtocols(runCtx, *minTVL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: protocol discovery: %v\n", err)
		return 2
	}
	log.Printf("scanner: %d protocols from Morpho vaults + DefiLlama",
		len(protocols))

	// ---- Stage 5: attach protocols to every vulnerable market. ----
	indexed := AttachProtocolsToMarkets(vulnerableMarkets, protocols)
	log.Printf("scanner: %d vulnerable markets after protocol attachment",
		len(indexed))

	if *minProt > 0 {
		indexed = FilterMarketsByProtocolCount(indexed, *minProt)
		log.Printf("scanner: %d markets after min-protocols=%d filter",
			len(indexed), *minProt)
	}

	// ---- Stage 6: dust filter on protocol lists. ----
	afterTVL := FilterProtocolsByTVL(indexed, *minTVL)
	log.Printf("scanner: %d markets after TVL filter (min=$%.0f)",
		len(afterTVL), *minTVL)

	// ---- Stage 7: differential probing on non-Morpho protocols.
	//      Protocols with no Morpho allocations are probed against
	//      their own bytecode and any AMM pools they reference. ----
	var probes []ProbeVerdict
	for _, p := range protocols {
		if len(p.Allocations) > 0 {
			// Morpho integrator: already covered by the
			// oracle-triage + Simulate path.
			continue
		}
		pv := ProbeProtocol(runCtx, client, rpcClient, p)
		probes = append(probes, pv)
		switch {
		case pv.Skipped:
			log.Printf("scanner[probe]: SKIP  %-30s (%s) %s",
				pv.Name, pv.Category, pv.SkipReason)
		case pv.AMMDependent:
			log.Printf("scanner[probe]: FLAG  %-30s (%s) %d func(s)",
				pv.Name, pv.Category, len(pv.DivergentFuncs))
		default:
			log.Printf("scanner[probe]: CLEAN %-30s (%s)",
				pv.Name, pv.Category)
		}
	}
	log.Printf("scanner[probe]: probed %d non-Morpho protocols", len(probes))

	// ---- Stage 8: fork confirmation on Morpho markets. ----
	confirmed, suspected := Simulate(runCtx, client, rpcClient, afterTVL)
	log.Printf("scanner: %d confirmed, %d suspected", len(confirmed), len(suspected))

	meta := RunMetadata{
		ChainID:              chainID.Int64(),
		BlockNumber:          blockNum,
		MarketsFromAPI:       len(markets),
		ProtocolsFromAPI:     len(protocols),
		MarketsAfterCountFlt: len(vulnerableMarkets),
		MarketsAfterTVLFlt:   len(afterTVL),
		MarketsVulnerable:    len(vulnerableMarkets),
		ConfirmedCount:       len(confirmed),
		SuspectedCount:       len(suspected),
		ProtocolsProbed:      len(probes),
	}

	rep, err := BuildReport(runCtx, client, meta, confirmed, suspected, probes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: build report: %v\n", err)
		return 2
	}
	return WriteReport(*outPath, *format, rep)
}

// writeEmptyReport is called when discovery returns nothing at all.
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
		ProtocolsProbed:      0,
	}
	rep, _ := BuildReport(context.Background(), nil, meta, nil, nil, nil)
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

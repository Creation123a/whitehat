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

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("scanner", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		rpcURL   = fs.String("rpc", "", "pre-running RPC URL; skips Anvil spawn")
		forkURL  = fs.String("fork-url", "", "Base RPC URL to fork (required unless --rpc)")
		forkBlock = fs.Uint64("fork-block", 0, "pinned fork block number (required unless --rpc)")
		anvilBin = fs.String("anvil", "anvil", "path to anvil binary")
		anvilPort = fs.Int("anvil-port", 8545, "anvil listen port")
		outPath  = fs.String("out", "report.json", "output file")
		format   = fs.String("format", "json", "output format: text | json")
		timeout  = fs.Duration("timeout", 30*time.Minute, "pipeline timeout")
		category = fs.String("category", "", "DefiLlama category keyword (Lending, Isolated Lending, Yield, Yield Aggregator, CDP, Leveraged Farming)")
	)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}

	if *category == "" {
		fmt.Fprintln(os.Stderr, "scanner: --category is required")
		return 1
	}
	if !TargetCategories[*category] {
		fmt.Fprintf(os.Stderr, "scanner: invalid category %q\n", *category)
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

	// ---- Anvil lifecycle ----
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

	// =========================================================
	// Phase 1: DefiLlama filter
	// =========================================================
	log.Printf("scanner[phase1]: fetching DefiLlama category=%q", *category)
	protocols, err := DiscoverProtocols(runCtx, *category)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner[phase1]: %v\n", err)
		return 2
	}
	log.Printf("scanner[phase1]: %d protocols in [%s] with Base TVL in [$50k, $10M]",
		len(protocols), *category)

	if len(protocols) == 0 {
		rep := BuildReport(RunMetadata{
			ChainID:         chainID.Int64(),
			BlockNumber:     blockNum,
			CategoryKeyword: *category,
			ProtocolsFound: 0,
		}, nil, nil)
		return WriteReport(*outPath, *format, rep)
	}

	// =========================================================
	// Phase 2 + 3 + 4: per-protocol pipeline
	// =========================================================
	var findings []FindingReport
	var skipped []SkippedProtocol
	totalFlags := 0
	scanned := 0

	for _, proto := range protocols {
		log.Printf("scanner[phase2]: resolving %q", proto.Name)

		addr, err := ResolveProtocolAddress(runCtx, proto.Name)
		if err != nil {
			log.Printf("scanner[phase2]: SKIP %q: %v", proto.Name, err)
			skipped = append(skipped, SkippedProtocol{Name: proto.Name, Slug: proto.Slug, Reason: err.Error()})
			continue
		}
		proto.Address = addr

		pricingAddrs, err := ScanPricingContracts(runCtx, client, proto)
		if err != nil {
			log.Printf("scanner[phase2]: SKIP %q: %v", proto.Name, err)
			skipped = append(skipped, SkippedProtocol{Name: proto.Name, Slug: proto.Slug, Reason: err.Error()})
			continue
		}

		log.Printf("scanner[phase3]: %q -> %d pricing contract(s)", proto.Name, len(pricingAddrs))
		scanned++

				var allFlags []FlagReport
		for _, paddr := range pricingAddrs {
			src, err := FetchVerifiedSource(runCtx, paddr)
			if err != nil {
				log.Printf("scanner[phase3]: %s source fetch failed: %v", paddr.Hex(), err)
				continue
			}

			flags := RunRegexScan(src) // now returns []FlagReport
			if len(flags) == 0 {
				continue
			}

			log.Printf("scanner[phase4]: %q -> %d flag(s), asking LLM", proto.Name, len(flags))
			for i := range flags {
				raw, err := AskGeminiWithFallback(runCtx, flags[i].Snippet)
				if err != nil {
					log.Printf("scanner[phase4]: LLM failed for rule %s: %v", flags[i].RuleID, err)
					flags[i].LLMVerdict = "ERROR"
					continue
				}
				flags[i].LLMVerdict = raw
				totalFlags++

				// Check the structured response for VULNERABLE.
				if ParseVerdict(raw) == "VULNERABLE" {
					allFlags = append(allFlags, flags[i])
				}
			}
		}

		if len(allFlags) > 0 {
			findings = append(findings, FindingReport{
				Protocol: proto.Name,
				Slug:     proto.Slug,
				Category: proto.Category,
				TVLUSD:   proto.TVLUSD,
				Address:  proto.Address.Hex(),
				Chain:    "base",
				Flags:    allFlags,
				Summary:  fmt.Sprintf("%d LLM-confirmed vulnerabilities", len(allFlags)),
			})
		}
	}

	log.Printf("scanner: scanned=%d skipped=%d findings=%d",
		scanned, len(skipped), len(findings))

	// =========================================================
	// Build + write report
	// =========================================================
	meta := RunMetadata{
		ChainID:          chainID.Int64(),
		BlockNumber:      blockNum,
		CategoryKeyword:  *category,
		ProtocolsFound:   len(protocols),
		ProtocolsScanned: scanned,
		TotalFlags:       totalFlags,
	}
	rep := BuildReport(meta, findings, skipped)
	return WriteReport(*outPath, *format, rep)
}

// =============================================================
// Dial helper
// =============================================================

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

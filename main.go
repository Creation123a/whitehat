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
	"github.com/ethereum/go-ethereum/crypto"
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
		rpcURL    = fs.String("rpc", "", "pre-running RPC URL")
		forkURL   = fs.String("fork-url", "", "Base RPC URL to fork")
		forkBlock = fs.Uint64("fork-block", 0, "pinned fork block")
		anvilBin  = fs.String("anvil", "anvil", "path to anvil binary")
		anvilPort = fs.Int("anvil-port", 8545, "anvil listen port")
		outPath   = fs.String("out", "report.json", "output file")
		format    = fs.String("format", "json", "output format: text | json")
		timeout   = fs.Duration("timeout", 150*time.Minute, "pipeline timeout")
		category  = fs.String("category", "", "DefiLlama category keyword")
	)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}

	if *category == "" || !TargetCategories[*category] {
		fmt.Fprintln(os.Stderr, "scanner: valid --category is required")
		return 1
	}

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancelRoot()
	}()

	// ---- Anvil Lifecycle ----
	var anvil *exec.Cmd
	effectiveRPC := *rpcURL
	if effectiveRPC == "" {
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
			if anvil.Process != nil {
				_ = anvil.Process.Signal(syscall.SIGTERM)
				_, _ = anvil.Process.Wait()
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
	exploiter := NewAnvilExploiter(client, rpcClient)

	runCtx, cancelRun := context.WithTimeout(rootCtx, *timeout)
	defer cancelRun()

	blockNum, err := client.BlockNumber(runCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: block number: %v\n", err)
		return 2
	}
	log.Printf("scanner: forked at block %d", blockNum)

	// Phase 1: Discovery
	protocols, err := DiscoverProtocols(runCtx, *category)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner[phase1]: %v\n", err)
		return 2
	}
	log.Printf("scanner[phase1]: Found %d protocols in [%s]", len(protocols), *category)

	if len(protocols) == 0 {
		rep := BuildReport(RunMetadata{ChainID: requiredChainID, BlockNumber: blockNum, CategoryKeyword: *category}, nil, nil)
		return WriteReport(*outPath, *format, rep)
	}

	var findings []FindingReport
	var skipped []SkippedProtocol
	totalFlags := 0
	scanned := 0

	for _, proto := range protocols {
		addrs := BaseProtocolRegistry[proto.Slug]
		if len(addrs) == 0 {
			log.Printf("scanner[phase1]: SKIPPED %q - no hardcoded addresses in registry", proto.Name)
			skipped = append(skipped, SkippedProtocol{Name: proto.Name, Slug: proto.Slug, Reason: "no hardcoded addresses"})
			continue
		}

		log.Printf("scanner[phase2]: Scanning protocol %q", proto.Name)
		visited := make(map[common.Address]bool)
		var protoFlags []FlagReport
		scannedSuccessfully := false

		for _, addr := range addrs {
			// v11.0: Pass depth=0 to initiate recursion
			if scanTarget(runCtx, client, rpcClient, effectiveRPC, exploiter, proto, addr, visited, &protoFlags, &totalFlags, 0) {
				scannedSuccessfully = true
			}
		}
		if !scannedSuccessfully {
			skipped = append(skipped, SkippedProtocol{Name: proto.Name, Slug: proto.Slug, Reason: "decompilation or RPC failed"})
			continue
		}

		scanned++
		if len(protoFlags) > 0 {
			findings = append(findings, FindingReport{
				Protocol: proto.Name,
				Slug:     proto.Slug,
				Category: proto.Category,
				TVLUSD:   proto.TVLUSD,
				Flags:    protoFlags,
			})
		}
	}

	meta := RunMetadata{
		ChainID:          requiredChainID,
		BlockNumber:      blockNum,
		CategoryKeyword:  *category,
		ProtocolsFound:   len(protocols),
		ProtocolsScanned: scanned,
		TotalFlags:       totalFlags,
	}
	rep := BuildReport(meta, findings, skipped)
	return WriteReport(*outPath, *format, rep)
}

// scanTarget executes the v11.0 Proof-Gatekeeper Pipeline.
func scanTarget(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	rpcURL string,
	exploiter *AnvilExploiter,
	proto Protocol,
	addr common.Address,
	visited map[common.Address]bool,
	flags *[]FlagReport,
	totalFlags *int,
	depth int,
) bool {
	// Depth guard
	if depth > maxTraversalDepth || visited[addr] {
		return false
	}
	visited[addr] = true

	// Step 1: Proxy Resolution
	impl := ResolveImplementation(ctx, client, addr)
	target := addr
	if impl != (common.Address{}) {
		target = impl
		log.Printf("scanner[proxy]: Resolved %s -> Impl %s", addr.Hex(), target.Hex())
	}

	// Step 2: Fetch Bytecode via RPC
	code, err := FetchBytecode(ctx, client, target)
	if err != nil || len(code) == 0 {
		log.Printf("scanner[source]: No bytecode at %s", target.Hex())
		return false
	}

	// Step 3: Classify
	role, _ := ClassifyContract(ctx, code)

	// Step 4: Expand dependencies (BATCHED SQD)
	dummyUser := common.HexToAddress("0x1111111111111111111111111111111111111111")
	deps := DiscoverLinkedContracts(ctx, client, target, code, dummyUser)
	
	var topic0Hashes []common.Hash
	for _, sig := range FactoryEventSignatures {
		topic0Hashes = append(topic0Hashes, crypto.Keccak256Hash([]byte(sig)))
	}
	
	// ONE call to SQD instead of 13
	sqdDeps, err := ScanFactoryEventsSQD(ctx, target, topic0Hashes)
	if err != nil {
		log.Printf("scanner[sqd]: Error fetching factory events: %v", err)
	} else {
		deps = append(deps, sqdDeps...)
	}

	// Step 5: Token short-circuit AFTER expansion
	if role == RoleToken {
		log.Printf("scanner[filter]: %s classified as RoleToken. Skipping further audit.", target.Hex())
		return true
	}

	// Step 6: BYTECODE RULES (before any proof)
	selectors := ExtractSelectorsFromBytecode(code)
	bcFlags := RunBytecodeRules(selectors)
	structuralTaint := len(bcFlags) > 0

	// Step 7: ANVIL PROOF GATE
	var exploitContext string
	var provenVuln bool

	// Run the generalized economic attack harness.
	exploitResult, err := exploiter.RunEconomicAttackHarness(ctx, target, role, deps)
	if err != nil {
		log.Printf("scanner[anvil]: Harness error: %v", err)
	} else if exploitResult != nil {
		provenVuln = true
		exploitContext = fmt.Sprintf("ANVIL ECONOMIC PROOF:\nType: %s\nTarget: %s\nProfit: %s wei\nDetails: %s\nTx: %s\n",
			exploitResult.AttackType, exploitResult.Target, exploitResult.ProfitWei.String(), exploitResult.Details, exploitResult.TxHash)
		log.Printf("scanner[anvil]: PROVEN EXPLOIT! Type: %s, Profit: %s", exploitResult.AttackType, exploitResult.ProfitWei.String())
	}

	// Step 9: Decompile ONLY if proven or tainted
	var src string
	if provenVuln || structuralTaint {
		log.Printf("scanner[heimdall]: Attempting decompilation for %s (Proven: %v, Tainted: %v)", target.Hex(), provenVuln, structuralTaint)
		decompiled, err := DecompileWithHeimdall(ctx, proto.Slug, target.Hex(), code, rpcURL, provenVuln, structuralTaint)
		if err != nil {
			log.Printf("scanner[heimdall]: FAILED to decompile %s: %v", target.Hex(), err)
		} else {
			src = decompiled
			log.Printf("scanner[heimdall]: Successfully decompiled %s (%d bytes)", target.Hex(), len(src))
		}
	}

	// Step 10 & 11: LLM — only if proven OR tainted
	if provenVuln || structuralTaint {
		if src != "" {
			chunks := ChunkByFunction(src)
			log.Printf("scanner[llm]: Split %s into %d chunks", target.Hex(), len(chunks))
			for _, chunk := range chunks {
				domain := ClassifyChunk(chunk)
				if domain != "lending" && domain != "oracle" && domain != "pricing" && domain != "vault" {
					continue
				}

				log.Printf("scanner[llm]: Sending %s chunk to Qwen...", domain)
				prompt := chunk
				if exploitContext != "" {
					prompt = fmt.Sprintf("PROOF:\n%s\n\nCODE:\n%s", exploitContext, chunk)
				}

				verdict, err := AskLocalLLM(ctx, prompt, proto.Name, string(role), domain, exploitContext)
				if err != nil {
					log.Printf("scanner[llm]: ERROR from Ollama: %v", err)
					continue
				}
				
				parsed := ParseVerdict(verdict)
				(*totalFlags)++
				if parsed == "VULNERABLE" || (structuralTaint && exploitContext == "") {
					*flags = append(*flags, FlagReport{
						RuleID:          "DYNAMIC_TRACE",
						Category:        domain,
						Severity:        "high",
						Snippet:         prompt,
						LLMVerdict:      verdict,
						ContractAddress: target.Hex(),
						ContractRole:    string(role),
					})
				}
			}
		} else {
			log.Printf("scanner[llm]: Skipping LLM for %s because decompilation returned empty source.", target.Hex())
		}
	}

	// Step 12: Attach bytecode-rule flags directly (no LLM needed)
	for _, f := range bcFlags {
		(*totalFlags)++
		f.ContractAddress = target.Hex()
		f.ContractRole = string(role)
		*flags = append(*flags, f)
	}

	return true
}


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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
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
		timeout   = fs.Duration("timeout", 45*time.Minute, "pipeline timeout")
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
			if scanTarget(runCtx, client, rpcClient, effectiveRPC, exploiter, proto, addr, visited, &protoFlags, &totalFlags) {
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

// scanTarget executes the full triaging pipeline on a single contract.
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
) bool {
	if visited[addr] {
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

	// Step 3: Discover Linked Contracts (Pools, Oracles, Comptrollers)
	selectorMap := GetSelectorMap(ctx, code)
	linkedContracts := DiscoverLinkedContracts(ctx, client, target, selectorMap)
	if len(linkedContracts) > 0 {
		for _, linked := range linkedContracts {
			scanTarget(ctx, client, rpcClient, rpcURL, exploiter, proto, linked, visited, flags, totalFlags)
		}
	}

	// Step 4: Bytecode Pre-Filter
	if isStandardToken(code) {
		if len(linkedContracts) == 0 {
			log.Printf("scanner[filter]: %s is a standard ERC-20/721 with no linked pools. Skipping.", target.Hex())
			return false
		}
		log.Printf("scanner[filter]: %s is a standard token, but we found linked pools. Skipping token logic, analyzing pools.", target.Hex())
		return true
	}

	// Step 5: Decompile with Heimdall
	log.Printf("scanner[heimdall]: Decompiling %s via RPC...", target.Hex())
	decompiledSrc, err := DecompileWithHeimdall(ctx, target.Hex(), rpcURL)
	if err != nil {
		log.Printf("scanner[heimdall]: Decompilation failed for %s: %v", target.Hex(), err)
		return false
	}
	src := decompiledSrc
	contractName := "DecompiledContract"

	// Step 6: Extract Dependencies from Source
	dependencies := ExtractDependencies(ctx, client, src, target)
	for _, dep := range dependencies {
		if !visited[dep] {
			log.Printf("scanner[state]: Discovered dependency in source %s", dep.Hex())
			scanTarget(ctx, client, rpcClient, rpcURL, exploiter, proto, dep, visited, flags, totalFlags)
		}
	}

	// Step 7: Static Triage (Regex & Mixed-Source)
	regexFlags := RunRegexScan(src)
	log.Printf("scanner[regex]: Triggered %d regex rules on %s", len(regexFlags), contractName)

	// Step 8: Dynamic Anvil Validation
	var exploitContext string

	// 8.1 Flash Loan AMM Distortion
	log.Printf("scanner[anvil]: Testing Flash Loan distortion on %s...", target.Hex())
	msg, err := exploiter.TestFlashLoanDistortion(ctx, target)
	if err == nil {
		log.Printf("scanner[anvil]: RESULT: %s", msg)
		exploitContext += "\nANVIL SIMULATION: " + msg + " No circuit breaker triggered.\n"
	} else {
		log.Printf("scanner[anvil]: Simulation skipped/failed: %v", err)
	}

	// 8.2 ERC-4626 Inflation
	log.Printf("scanner[anvil]: Testing ERC-4626 inflation on %s...", target.Hex())
	attacker := common.HexToAddress("0x1111111111111111111111111111111111111111")
	victim := common.HexToAddress("0x2222222222222222222222222222222222222222")
	
	vulnerable, err := exploiter.TestERC4626Inflation(ctx, target, attacker, victim)
	if err == nil && vulnerable {
		log.Printf("scanner[anvil]: VULNERABLE! Victim received 0 shares.")
		exploitContext += "\nANVIL SIMULATION: ERC-4626 First Depositor Inflation attack succeeded. Victim received 0 shares.\n"
	} else if err == nil {
		log.Printf("scanner[anvil]: SAFE. Inflation attack failed or not a valid 4626 vault.")
	}

	// 8.3 Liquidation Simulation
	// Find a linked oracle from the discovered linked contracts
	var oracleAddr common.Address
	for _, linked := range linkedContracts {
		linkedCode, _ := client.CodeAt(ctx, linked, nil)
		hexLinked := common.Bytes2Hex(linkedCode)
		if strings.Contains(hexLinked, "50d25bcd") || strings.Contains(hexLinked, "feaf968c") {
			oracleAddr = linked
			break
		}
	}
	
	if oracleAddr != (common.Address{}) {
		log.Printf("scanner[anvil]: Testing liquidation simulation on %s using oracle %s...", target.Hex(), oracleAddr.Hex())
		liqVulnerable, err := exploiter.TestLiquidationSimulation(ctx, target, oracleAddr, victim)
		if err == nil && liqVulnerable {
			log.Printf("scanner[anvil]: VULNERABLE! Liquidation succeeded after price crash.")
			exploitContext += "\nANVIL SIMULATION: Liquidation succeeded after a 90% oracle price crash.\n"
		}
	}

	// Step 9: Segmented LLM Analytics (Chunking & Domain Prompts)
	chunks := ChunkByFunction(src)
	log.Printf("scanner[chunk]: Split contract into %d function chunks", len(chunks))

	for i, chunk := range chunks {
		domain := ClassifyChunk(chunk)
		log.Printf("scanner[chunk]: Chunk %d classified as [%s]", i+1, domain)
		
		// Only send chunks that have potential math or oracle logic to the LLM
		if domain == "general" && !strings.Contains(chunk, "Unresolved_") {
			continue 
		}

		fullPrompt := chunk
		// Append any regex flags that fall within this chunk for extra context
		for _, f := range regexFlags {
			if strings.Contains(chunk, f.Snippet) {
				fullPrompt = fmt.Sprintf("REGEX FINDING (%s):\n%s\n\n%s", f.RuleID, f.Snippet, chunk)
				break
			}
		}
		
		// Append Anvil context if relevant to this chunk
		if exploitContext != "" && (domain == "lending" || domain == "oracle") {
			fullPrompt += "\n\n" + exploitContext
		}

		log.Printf("scanner[llm]: Sending chunk %d (%d bytes) to Qwen...", i+1, len(fullPrompt))
		
		verdict, err := AskLocalLLM(ctx, fullPrompt, contractName, "Target Contract", domain)
		if err == nil {
			parsedVerdict := ParseVerdict(verdict)
			log.Printf("scanner[llm]: Qwen Verdict -> %s", parsedVerdict)
			
			flag := FlagReport{
				RuleID:          "DYNAMIC_TRACE",
				Category:        domain,
				Severity:        "high",
				Snippet:         fullPrompt,
				LLMVerdict:      verdict,
				ContractAddress: target.Hex(),
				ContractRole:    "main",
			}
			(*totalFlags)++
			if parsedVerdict == "VULNERABLE" {
				*flags = append(*flags, flag)
			}
		} else {
			log.Printf("scanner[llm]: error: %v", err)
		}
	}

	return true
}

// isStandardToken checks if the bytecode is just a standard ERC-20/721.
func isStandardToken(code []byte) bool {
	hexCode := common.Bytes2Hex(code)
	
	hasTransfer := strings.Contains(hexCode, "a9059cbb")
	hasApprove := strings.Contains(hexCode, "095ea7b3")
	
	hasAmmMath := strings.Contains(hexCode, "3850c7bd") || 
			      strings.Contains(hexCode, "0902f1ac") || 
			      strings.Contains(hexCode, "bb7b8b80")

	hasLendingMath := strings.Contains(hexCode, "b3596f07") || 
			          strings.Contains(hexCode, "fc57d4df") || 
			          strings.Contains(hexCode, "8a889156") || 
			          strings.Contains(hexCode, "50d25bcd") || 
			          strings.Contains(hexCode, "a035b1fe")

	return hasTransfer && hasApprove && !hasAmmMath && !hasLendingMath
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

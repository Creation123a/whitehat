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
		timeout   = fs.Duration("timeout", 120*time.Minute, "pipeline timeout") // Increased to 120m
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

	// Step 3: Discover Linked Contracts
	selectorMap := GetSelectorMap(ctx, code)
	linkedContracts := DiscoverLinkedContracts(ctx, client, target, selectorMap)
	
	// Step 4: Bytecode Pre-Filter
	if isStandardToken(code) && len(linkedContracts) == 0 {
		log.Printf("scanner[filter]: %s is a standard ERC-20/721 with no linked pools. Skipping.", target.Hex())
		return false
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

	// Step 7: Static Triage
	regexFlags := RunRegexScan(src)
	log.Printf("scanner[regex]: Triggered %d regex rules on %s", len(regexFlags), contractName)

	// Directly add critical structural flaws (like Mixed Source)
	for _, f := range regexFlags {
		if f.RuleID == "MIXED_SOURCE_CHUNK" {
			log.Printf("scanner[regex]: PROVEN STRUCTURAL FLAW: MIXED_SOURCE on %s", target.Hex())
			(*totalFlags)++
			*flags = append(*flags, f)
		}
	}

	// Step 8: Identify Anvil Targets (AMM, Oracle, Lending Pool)
	var ammPool, protocolOracle, protocolPool common.Address
	
	checkTarget := func(c []byte, t common.Address) {
		hexC := common.Bytes2Hex(c)
		if strings.Contains(hexC, "0902f1ac") || strings.Contains(hexC, "3850c7bd") {
			if ammPool == (common.Address{}) { ammPool = t }
		}
		if strings.Contains(hexC, "50d25bcd") || strings.Contains(hexC, "feaf968c") {
			if protocolOracle == (common.Address{}) { protocolOracle = t }
		}
		if strings.Contains(hexC, "5ec88c79") || strings.Contains(hexC, "bf92857c") {
			if protocolPool == (common.Address{}) { protocolPool = t }
		}
	}

	// Check the target, linked state variables, and decompiled dependencies
	checkTarget(code, target)
	for _, linked := range linkedContracts {
		linkedCode, _ := client.CodeAt(ctx, linked, nil)
		checkTarget(linkedCode, linked)
	}
	for _, dep := range dependencies {
		depCode, _ := client.CodeAt(ctx, dep, nil)
		checkTarget(depCode, dep)
	}

	// Step 9: Anvil Simulation & Proof Generation
	var exploitContext string
	if ammPool != (common.Address{}) && protocolOracle != (common.Address{}) && protocolPool != (common.Address{}) {
		log.Printf("scanner[anvil]: Found AMM (%s), Oracle (%s), and Pool (%s). Running Oracle Manipulation Proof...", ammPool.Hex(), protocolOracle.Hex(), protocolPool.Hex())
		
		dummyUser := common.HexToAddress("0x1111111111111111111111111111111111111111")
		isVuln, proof, err := exploiter.TestOracleManipulation(ctx, ammPool, protocolOracle, protocolPool, dummyUser)
		
		if err == nil && isVuln {
			exploitContext = fmt.Sprintf("ANVIL PROOF: %s\n", proof)
			log.Printf("scanner[anvil]: PROVEN EXPLOIT! %s", proof)
		} else if err != nil {
			log.Printf("scanner[anvil]: Oracle manipulation proof failed: %v", err)
		} else {
			log.Printf("scanner[anvil]: Oracle manipulation did not break protocol. %s", proof)
		}
	} else {
		log.Printf("scanner[anvil]: Could not identify full AMM/Oracle/Pool triplet. Skipping Oracle Manipulation.")
	}

	// Step 10: LLM Analytics (Only if we have an Anvil Proof)
	chunks := ChunkByFunction(src)
	log.Printf("scanner[chunk]: Split contract into %d function chunks", len(chunks))

	for i, chunk := range chunks {
		domain := ClassifyChunk(chunk)
		
		// Only send to LLM if we have an Anvil proof and the chunk is related to math/oracle/lending.
		if exploitContext == "" || (domain != "lending" && domain != "oracle" && domain != "pricing") {
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

		log.Printf("scanner[llm]: Sending proven-vulnerable chunk %d (%d bytes) to Qwen...", i+1, len(fullPrompt))
		
		// Pass exploitContext to the LLM to force root-cause analysis
		verdict, err := AskLocalLLM(ctx, fullPrompt, contractName, "Target Contract", domain, exploitContext)
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

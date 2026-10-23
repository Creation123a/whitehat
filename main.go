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

	// Loop through all protocols
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
	
	// Step 3: Bytecode Pre-Filter
	if isStandardToken(code) {
		log.Printf("scanner[filter]: %s is a standard ERC-20/721. Skipping.", target.Hex())
		return false 
	}

	// Step 4: Decompile with Heimdall
	log.Printf("scanner[heimdall]: Decompiling %s via RPC...", target.Hex())
	decompiledSrc, err := DecompileWithHeimdall(ctx, target.Hex(), rpcURL)
	if err != nil {
		log.Printf("scanner[heimdall]: Decompilation failed for %s: %v", target.Hex(), err)
		return false
	}
	src := decompiledSrc
	contractName := "DecompiledContract"

	// Step 5: Dynamic Dependency Traversal
	dependencies := ExtractDependencies(ctx, client, src, target)
	for _, dep := range dependencies {
		log.Printf("scanner[state]: Discovered dependency %s", dep.Hex())
		scanTarget(ctx, client, rpcClient, rpcURL, exploiter, proto, dep, visited, flags, totalFlags)
	}

	// Phase 1: Static Triage (Regex only)
	regexFlags := RunRegexScan(src)
	log.Printf("scanner[regex]: Triggered %d regex rules on %s", len(regexFlags), contractName)

	var combinedContext strings.Builder
	for _, f := range regexFlags {
		log.Printf("scanner[regex]: FLAG [%s] on line %d", f.RuleID, f.LineStart)
		combinedContext.WriteString(fmt.Sprintf("REGEX FINDING (%s):\n%s\n", f.RuleID, f.Snippet))
	}

	// Phase 2: Dynamic Anvil Validation
	var exploitContext string

	// 1. Flash Loan AMM Distortion
	log.Printf("scanner[anvil]: Testing Flash Loan distortion on %s...", target.Hex())
	msg, err := exploiter.TestFlashLoanDistortion(ctx, target)
	if err == nil {
		log.Printf("scanner[anvil]: RESULT: %s", msg)
		exploitContext += "\nANVIL SIMULATION: " + msg + " No circuit breaker triggered.\n"
	} else {
		log.Printf("scanner[anvil]: Simulation skipped/failed: %v", err)
	}

	// 2. ERC-4626 Inflation Attack
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

	// Phase 3: Segmented LLM Analytics
	if combinedContext.Len() > 0 || exploitContext != "" {
		fullPrompt := combinedContext.String() + exploitContext
		log.Printf("scanner[llm]: Sending %d bytes of context to Qwen...", len(fullPrompt))
		
		verdict, err := AskLocalLLM(ctx, fullPrompt, contractName, "Target Contract")
		if err == nil {
			parsedVerdict := ParseVerdict(verdict)
			log.Printf("scanner[llm]: Qwen Verdict -> %s", parsedVerdict)
			
			flag := FlagReport{
				RuleID:          "DYNAMIC_TRACE",
				Category:        "combined",
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
	
	// Check for AMM Math
	hasAmmMath := strings.Contains(hexCode, "3850c7bd") || // slot0
			      strings.Contains(hexCode, "0902f1ac") || // getReserves
			      strings.Contains(hexCode, "bb7b8b80")    // get_virtual_price

	// Check for Lending/Oracle Math
	hasLendingMath := strings.Contains(hexCode, "b3596f07") || // getAssetPrice (Aave)
			          strings.Contains(hexCode, "fc57d4df") || // getUnderlyingPrice (Compound/Sonne)
			          strings.Contains(hexCode, "8a889156") || // latestRoundData (Chainlink)
			          strings.Contains(hexCode, "50d25bcd") || // latestAnswer
			          strings.Contains(hexCode, "a035b1fe")    // price() (Morpho)

	// If it has transfer and approve but NO amm math and NO lending math, it's just a token.
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

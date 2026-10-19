package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
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

	protocols, err := DiscoverProtocols(runCtx, *category)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner[phase1]: %v\n", err)
		return 2
	}
	log.Printf("scanner[phase1]: %d protocols in [%s]", len(protocols), *category)

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
			skipped = append(skipped, SkippedProtocol{Name: proto.Name, Slug: proto.Slug, Reason: "no hardcoded addresses"})
			continue
		}

		log.Printf("scanner[phase2]: Scanning protocol %q", proto.Name)
		visited := make(map[common.Address]bool)
		var protoFlags []FlagReport
		scannedSuccessfully := false

		for _, addr := range addrs {
			if scanTarget(runCtx, client, exploiter, proto, addr, visited, &protoFlags, &totalFlags) {
				scannedSuccessfully = true
			}
		}

		if !scannedSuccessfully {
			skipped = append(skipped, SkippedProtocol{Name: proto.Name, Slug: proto.Slug, Reason: "source not verified or compilation failed"})
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

// scanTarget executes the 3-phase triaging pipeline on a single contract.
func scanTarget(
	ctx context.Context,
	client *ethclient.Client,
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

	// Step 2: Proxy Resolution
	impl := ResolveImplementation(ctx, client, addr)
	target := addr
	if impl != (common.Address{}) {
		target = impl
	}

	// Step 3: Bytecode Pre-Filter (Skip ERC-20s, require Math/Oracle selectors)
	code, err := client.CodeAt(ctx, target, nil)
	if err != nil || len(code) == 0 {
		return false
	}
	if isStandardToken(code) {
		return false // Skip standard tokens
	}

	// Download Source Code
	src, contractName, err := FetchVerifiedSource(ctx, client, target)
	if err != nil {
		log.Printf("scanner[source]: %s: %v", target.Hex(), err)
		return false
	}

	// Step 4: State Variable Reader (Find Oracles/Managers dynamically)
	dependencies := ReadStateDependencies(ctx, client, target)
	for _, dep := range dependencies {
		log.Printf("scanner[state]: Discovered dependency %s", dep.Hex())
		// Recursively scan dependencies (Oracles, RateProviders)
		scanTarget(ctx, client, exploiter, proto, dep, visited, flags, totalFlags)
	}

	// Phase 1: Static Triage (Slither/Aderyn + Regex)
	slitherSummary, _ := RunStaticAnalyzers(src, contractName)
	regexFlags := RunRegexScan(src)

	var combinedContext strings.Builder
	if slitherSummary != "" && slitherSummary != "No high/critical issues found by static analyzers." {
		combinedContext.WriteString("STATIC ANALYZER FINDINGS:\n" + slitherSummary + "\n")
	}
	for _, f := range regexFlags {
		combinedContext.WriteString(fmt.Sprintf("REGEX FINDING (%s):\n%s\n", f.RuleID, f.Snippet))
	}

		// Phase 2: Dynamic Anvil Validation
	var exploitContext string
	
		// Example 1: Check if this looks like an AMM pool or Oracle
	isOracleOrPool := strings.Contains(strings.ToLower(contractName), "oracle") || 
	                  strings.Contains(strings.ToLower(contractName), "price") ||
	                  strings.Contains(strings.ToLower(contractName), "pool") ||
	                  strings.Contains(strings.ToLower(contractName), "pair")
	                  
	if isOracleOrPool {
		log.Printf("scanner[anvil]: Simulating flash loan distortion on %s", target.Hex())
		
		msg, err := exploiter.TestFlashLoanDistortion(ctx, target)
		if err == nil {
			exploitContext += "\nANVIL SIMULATION: " + msg + " No circuit breaker triggered.\n"
		}
	}

	// Example 2: ERC-4626 Inflation Attack (If contract looks like a vault)
	isVault := strings.Contains(strings.ToLower(contractName), "vault") || 
	           strings.Contains(strings.ToLower(contractName), "4626")
	           
	if isVault {
		log.Printf("scanner[anvil]: Testing ERC-4626 inflation on %s", target.Hex())
		// We use dummy addresses for the attacker and victim
		attacker := common.HexToAddress("0x1111111111111111111111111111111111111111")
		victim := common.HexToAddress("0x2222222222222222222222222222222222222222")
		// Assuming target is the vault, and we pull the underlying asset from the ABI (dummy for now)
		dummyAsset := common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") // Default to USDC
		
		vulnerable, _ := exploiter.TestERC4626Inflation(ctx, target, dummyAsset, attacker, victim)
		if vulnerable {
			exploitContext += "\nANVIL SIMULATION: ERC-4626 First Depositor Inflation attack succeeded. Victim received 0 shares.\n"
		}
	}
	// Phase 3: Segmented LLM Analytics
	if combinedContext.Len() > 0 || exploitContext != "" {
		fullPrompt := combinedContext.String() + exploitContext
		log.Printf("scanner[llm]: Sending %d bytes of context to Qwen...", len(fullPrompt))
		
		verdict, err := AskLocalLLM(ctx, fullPrompt, contractName, "Target Contract")
		if err == nil {
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
			if ParseVerdict(verdict) == "VULNERABLE" {
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
	hasTransfer := strings.Contains(common.Bytes2Hex(code), "a9059cbb")
	hasApprove := strings.Contains(common.Bytes2Hex(code), "095ea7b3")
	hasMath := strings.Contains(common.Bytes2Hex(code), "3850c7bd") || // slot0
			   strings.Contains(common.Bytes2Hex(code), "0902f1ac") || // getReserves
			   strings.Contains(common.Bytes2Hex(code), "8a889156")    // latestRoundData

	// If it has transfer and approve but NO math/oracle selectors, it's just a token.
	return hasTransfer && hasApprove && !hasMath
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

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
	"github.com/ethereum/go-ethereum/common/hexutil"
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
		timeout   = fs.Duration("timeout", 120*time.Minute, "pipeline timeout")
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
			if scanTarget(runCtx, client, rpcClient, effectiveRPC, exploiter, proto, addr, visited, &protoFlags, &totalFlags, 0, blockNum) {
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

// =============================================================
// v11.0 Core Target Scanner
// =============================================================

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
	blockNum uint64,
) bool {
	if depth > maxTraversalDepth || visited[addr] {
		return false
	}
	visited[addr] = true

	// 1. Proxy Resolution
	target := addr
	if impl := ResolveImplementation(ctx, client, addr); impl != (common.Address{}) && !visited[impl] {
		target = impl
		visited[impl] = true
	}

	// 2. Fetch Bytecode
	code, err := FetchBytecode(ctx, client, target)
	if err != nil || len(code) == 0 {
		return false
	}

	// 3. Classify Contract
	role, _ := ClassifyContract(ctx, code)

	// 4. Expand Dependencies (ALWAYS)
	dummyUser := common.HexToAddress("0x1111111111111111111111111111111111111111")
	deps := DiscoverLinkedContracts(ctx, client, target, code, dummyUser)
	
	// Add Factory Events discovery
	factoryDeps := ScanFactoryEvents(ctx, client, target, big.NewInt(0), nil) // 0 to latest
	deps = append(deps, factoryDeps...)

	for _, dep := range deps {
		if !visited[dep] {
			scanTarget(ctx, client, rpcClient, rpcURL, exploiter, proto, dep, visited, flags, totalFlags, depth+1, blockNum)
		}
	}

	// 5. Token Short-Circuit (AFTER expansion)
	if role == RoleToken {
		return true
	}

	// 6. Bytecode Rules (Pre-Decompilation)
	selectors := ExtractSelectorsFromBytecode(code)
	bcFlags := RunBytecodeRules(selectors)
	structuralTaint := len(bcFlags) > 0

	// 7. Anvil Proof Gate
	var exploitContext string
	var provenVuln bool
	attacker := common.HexToAddress("0x2222222222222222222222222222222222222222")
	victim := common.HexToAddress("0x3333333333333333333333333333333333333333")

	// 7a. Oracle Manipulation
	ammPool, oracle, pool := identifyTriplet(deps, ctx, client)
	if ammPool != (common.Address{}) && oracle != (common.Address{}) && pool != (common.Address{}) {
		healthAddr, _ := ResolveHealthCheckTarget(ctx, client, pool)
		if healthAddr != (common.Address{}) {
			vuln, proof, err := exploiter.TestOracleManipulation(ctx, ammPool, oracle, healthAddr, dummyUser)
			if err == nil && vuln {
				provenVuln = true
				exploitContext += "ANVIL: " + proof + "\n"
				log.Printf("scanner[anvil]: PROVEN EXPLOIT! %s", proof)
			}
		}
	}

	// 7b. ERC-4626 Inflation
	if role == RoleVault {
		asset := GetVaultAsset(ctx, client, target)
		if asset == (common.Address{}) {
			asset = common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") // default USDC
		}
		vuln, _ := exploiter.TestERC4626Inflation(ctx, target, attacker, victim)
		if vuln {
			provenVuln = true
			exploitContext += "ANVIL: ERC-4626 inflation proven\n"
			log.Printf("scanner[anvil]: PROVEN EXPLOIT! ERC-4626 inflation on %s", target.Hex())
		}
	}

	// 8. HEVM Fallback
	if !provenVuln {
		sig, assertion := invariantFor(role)
		if sig != "" {
			vuln, proof, err := exploiter.TestSymbolicInvariant(ctx, target, hexutil.Encode(code), sig, assertion, rpcURL, blockNum)
			if err == nil && vuln {
				provenVuln = true
				exploitContext += "HEVM: " + proof + "\n"
				log.Printf("scanner[hevm]: PROVEN EXPLOIT! %s", proof)
			}
		}
	}

	// 9. Decompile (ONLY if proven or tainted)
	var src string
	if provenVuln || structuralTaint {
		var err error
		src, err = DecompileWithHeimdall(ctx, proto.Slug, target.Hex(), code, rpcURL, provenVuln, structuralTaint)
		if err != nil {
			log.Printf("scanner[heimdall]: Failed to decompile %s: %v", target.Hex(), err)
		}
	}

	// 10. Regex Scan (Secondary signal)
	var regexFlags []FlagReport
	if src != "" {
		regexFlags = RunRegexScan(src)
		log.Printf("scanner[regex]: Triggered %d regex rules on %s", len(regexFlags), target.Hex())
	}

	// 11. LLM Analytics (Only if proven OR tainted)
	if provenVuln || structuralTaint {
		chunks := ChunkByFunction(src)
		for i, chunk := range chunks {
			domain := ClassifyChunk(chunk)
			
			// If we are here because of structural taint but have no proof, force the LLM to analyze the relevant domains
			if exploitContext == "" && (domain != "lending" && domain != "oracle" && domain != "pricing" && domain != "vault") {
				continue
			}
			if exploitContext != "" && (domain != "lending" && domain != "oracle" && domain != "pricing" && domain != "vault") {
				continue
			}

			fullPrompt := chunk
			for _, f := range regexFlags {
				if strings.Contains(chunk, f.Snippet) {
					fullPrompt = fmt.Sprintf("REGEX FINDING (%s):\n%s\n\n%s", f.RuleID, f.Snippet, chunk)
					break
				}
			}

			contextToPass := exploitContext
			if contextToPass == "" {
				contextToPass = "STRUCTURAL_TAINT: Bytecode rules flagged this contract."
			}

			verdict, err := AskLocalLLM(ctx, fullPrompt, "Target Contract", string(role), domain, contextToPass)
			if err == nil {
				parsedVerdict := ParseVerdict(verdict)
				
				flag := FlagReport{
					RuleID:          "DYNAMIC_TRACE",
					Category:        domain,
					Severity:        "high",
					Snippet:         fullPrompt,
					LLMVerdict:      verdict,
					ContractAddress: target.Hex(),
					ContractRole:    string(role),
				}
				(*totalFlags)++
				if parsedVerdict == "VULNERABLE" || (structuralTaint && exploitContext == "") {
					*flags = append(*flags, flag)
				}
			}
		}
	}

	// 12. Attach Bytecode Flags
	for _, f := range bcFlags {
		(*totalFlags)++
		f.ContractAddress = target.Hex()
		f.ContractRole = string(role)
		*flags = append(*flags, f)
	}

	return true
}

// =============================================================
// Helpers
// =============================================================

// identifyTriplet scans the dependencies to find the AMM, Oracle, and Lending Pool.
func identifyTriplet(deps []common.Address, ctx context.Context, client *ethclient.Client) (common.Address, common.Address, common.Address) {
	var ammPool, oracle, pool common.Address
	for _, dep := range deps {
		code, err := client.CodeAt(ctx, dep, nil)
		if err != nil || len(code) == 0 {
			continue
		}
		selCounts := ExtractSelectorsFromBytecode(code)
		
		if ammPool == (common.Address{}) {
			if selCounts[0x0902f1ac] || selCounts[0x3850c7bd] { // getReserves, slot0
				ammPool = dep
			}
		}
		if oracle == (common.Address{}) {
			if selCounts[0xfeaf968c] || selCounts[0x50d25bcd] { // latestRoundData, latestAnswer
				oracle = dep
			}
		}
		if pool == (common.Address{}) {
			if selCounts[0x5ec88c79] || selCounts[0xbf92857c] { // getAccountLiquidity, getUserAccountData
				pool = dep
			}
		}
	}
	return ammPool, oracle, pool
}

// invariantFor maps a contract role to a hevm signature and economic assertion.
func invariantFor(role ContractRole) (string, string) {
	switch role {
	case RoleVault:
		return "deposit(uint256,address)", "totalAssets() >= totalSupply()"
	case RoleLending:
		return "borrow(uint256)", "healthFactor() >= 1e18"
	case RoleAMM:
		return "swap(uint256,uint256,address,bytes)", "getReserves().0 > 0 && getReserves().1 > 0"
	case RoleMathOracle:
		return "update()", "latestAnswer() > 0"
	default:
		return "", ""
	}
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

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
	blockNum uint64,
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

	// Step 4: Expand dependencies (ALWAYS, before any audit)
	dummyUser := common.HexToAddress("0x1111111111111111111111111111111111111111")
	deps := DiscoverLinkedContracts(ctx, client, target, code, dummyUser)
	deps = append(deps, ScanFactoryEvents(ctx, client, target, nil, nil)...)

	// Recurse
	for _, dep := range deps {
		if !visited[dep] {
			scanTarget(ctx, client, rpcClient, rpcURL, exploiter, proto, dep, visited, flags, totalFlags, depth+1, blockNum)
		}
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

	// Step 7: ANVIL PROOF GATE (before Heimdall)
	var exploitContext string
	var provenVuln bool

	// 7a. Identify triplet for Oracle Manipulation
	var ammPool, protocolOracle, protocolPool common.Address
	checkTarget := func(c []byte, t common.Address) {
		hexC := common.Bytes2Hex(c)
		if strings.Contains(hexC, "0902f1ac") || strings.Contains(hexC, "3850c7bd") {
			if ammPool == (common.Address{}) {
				ammPool = t
			}
		}
		if strings.Contains(hexC, "50d25bcd") || strings.Contains(hexC, "feaf968c") {
			if protocolOracle == (common.Address{}) {
				protocolOracle = t
			}
		}
		if strings.Contains(hexC, "5ec88c79") || strings.Contains(hexC, "bf92857c") {
			if protocolPool == (common.Address{}) {
				protocolPool = t
			}
		}
	}

	checkTarget(code, target)
	for _, dep := range deps {
		depCode, _ := client.CodeAt(ctx, dep, nil)
		checkTarget(depCode, dep)
	}

	if ammPool != (common.Address{}) && protocolOracle != (common.Address{}) && protocolPool != (common.Address{}) {
		healthAddr, _ := ResolveHealthCheckTarget(ctx, client, protocolPool)
		if healthAddr != (common.Address{}) {
			vuln, proof, _ := exploiter.TestOracleManipulation(ctx, ammPool, protocolOracle, healthAddr, dummyUser)
			if vuln {
				provenVuln = true
				exploitContext += "ANVIL: " + proof + "\n"
			}
		}
	}

	// 7b. ERC-4626 Inflation for vaults
	if role == RoleVault {
		asset := GetVaultAsset(ctx, client, target)
		if asset != (common.Address{}) {
			vuln, _ := exploiter.TestERC4626Inflation(ctx, target, dummyUser, common.HexToAddress("0x2222222222222222222222222222222222222222"))
			if vuln {
				provenVuln = true
				exploitContext += "ANVIL: ERC-4626 inflation proven\n"
			}
		}
	}

	// Step 8: HEVM FALLBACK (if Anvil could not prove or assemble)
	if !provenVuln {
		var sig, assertion string
		switch role {
		case RoleVault:
			sig, assertion = "deposit(uint256,address)", "totalAssets() >= totalSupply()"
		case RoleLending:
			sig, assertion = "borrow(uint256)", "getAccountLiquidity(address(this)).2 == 0" // checking shortfall
		case RoleAMM:
			sig, assertion = "swap(uint256,uint256,address,bytes)", "getReserves().0 > 0 && getReserves().1 > 0"
		}

		if sig != "" {
			hexCode := hexutil.Encode(code)
			vuln, proof, err := exploiter.TestSymbolicInvariant(ctx, target, hexCode, sig, assertion, rpcURL, blockNum)
			if err == nil && vuln {
				provenVuln = true
				exploitContext += "HEVM: " + proof + "\n"
			}
		}
	}

	// Step 9: Decompile ONLY if proven or tainted
	var src string
	if provenVuln || structuralTaint {
		decompiled, err := DecompileWithHeimdall(ctx, proto.Slug, target.Hex(), code, rpcURL, provenVuln, structuralTaint)
		if err == nil {
			src = decompiled
		}
	}


	// Step 10 & 11: LLM — only if proven OR tainted
	if provenVuln || structuralTaint {
		if src != "" {
			chunks := ChunkByFunction(src)
			// FIX: Changed `for i, chunk` to `for _, chunk` (i was unused)
			for _, chunk := range chunks {
				domain := ClassifyChunk(chunk)
				if domain != "lending" && domain != "oracle" && domain != "pricing" && domain != "vault" {
					continue
				}

				prompt := chunk
				if exploitContext != "" {
					prompt = fmt.Sprintf("PROOF:\n%s\n\nCODE:\n%s", exploitContext, chunk)
				}

				verdict, err := AskLocalLLM(ctx, prompt, proto.Name, string(role), domain, exploitContext)
				if err == nil {
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
			}
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

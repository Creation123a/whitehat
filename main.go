package main

import (
	"context"
	"errors"
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

const maxChildrenPerProtocol = 50

func main() { os.Exit(run()) }

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

	if err := fs.Parse(os.Args[1:]); err != nil { return 1 }
	if *category == "" || !TargetCategories[*category] {
		fmt.Fprintln(os.Stderr, "scanner: valid --category is required")
		return 1
	}

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigCh; cancelRoot() }()

	var anvil *exec.Cmd
	effectiveRPC := *rpcURL
	if effectiveRPC == "" {
		anvil = exec.Command(*anvilBin,
			"--fork-url", *forkURL,
			"--fork-block-number", fmt.Sprintf("%d", *forkBlock),
			"--port", fmt.Sprintf("%d", *anvilPort),
			"--chain-id", fmt.Sprintf("%d", requiredChainID),
			"--fork-retry-backoff", "2000", "--retries", "10", "--timeout", "60000",
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
	if err != nil { fmt.Fprintf(os.Stderr, "scanner: rpc connect: %v\n", err); return 1 }
	defer rpcClient.Close()

	client := ethclient.NewClient(rpcClient)
	exploiter, err := NewAnvilExploiter(client, rpcClient)
	if err != nil { fmt.Fprintf(os.Stderr, "scanner: exploiter: %v\n", err); return 1 }

	runCtx, cancelRun := context.WithTimeout(rootCtx, *timeout)
	defer cancelRun()

	blockNum, err := client.BlockNumber(runCtx)
	if err != nil { fmt.Fprintf(os.Stderr, "scanner: block number: %v\n", err); return 2 }
	log.Printf("scanner: forked at block %d", blockNum)

	protocols, err := DiscoverProtocols(runCtx, *category)
	if err != nil { fmt.Fprintf(os.Stderr, "scanner[phase1]: %v\n", err); return 2 }
	log.Printf("scanner[phase1]: Found %d protocols in [%s]", len(protocols), *category)

	if len(protocols) == 0 {
		rep := BuildReport(RunMetadata{ChainID: requiredChainID, BlockNumber: blockNum, CategoryKeyword: *category}, nil, nil, nil)
		return WriteReport(*outPath, *format, rep)
	}

	var findings []FindingReport
	var leads []LeadReport
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
		var protoLeads []LeadReport
		scannedSuccessfully := false

		for _, addr := range addrs {
			if scanTarget(runCtx, client, rpcClient, effectiveRPC, exploiter, proto, addr,
				visited, &protoFlags, &protoLeads, &totalFlags, 0, blockNum) {
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
				Protocol: proto.Name, Slug: proto.Slug, Category: proto.Category,
				TVLUSD: proto.TVLUSD, Flags: protoFlags,
			})
		}
		leads = append(leads, protoLeads...)
	}

	meta := RunMetadata{
		ChainID: requiredChainID, BlockNumber: blockNum,
		CategoryKeyword: *category, ProtocolsFound: len(protocols),
		ProtocolsScanned: scanned, TotalFlags: totalFlags,
	}
	rep := BuildReport(meta, findings, leads, skipped)
	return WriteReport(*outPath, *format, rep)
}

// scanTarget executes the v11.0 Proof-Gatekeeper Pipeline for a single
// target (and recursively for its discovered dependencies).
//
// Pipeline order:
//   1. Depth/visited guard
//   2. Proxy resolution (EIP-1967 / legacy / EIP-1167)
//   3. Bytecode fetch + role classification
//   4. Dependency discovery (evmole view calls + SQD factory events)
//   5. Bounded recursion into dependencies
//   6. Token short-circuit
//   7. Bytecode-level structural rules (pre-decompile)
//   8. Anvil economic proof gate
//   9. Medusa invariant proof gate
//  10. Heimdall decompile (gated by proof OR taint)
//  11. LLM root-cause analysis (gated by proof OR taint)
//  12. Regex tier over decompiled source (leads only)
//  13. Bytecode leads emitted
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
	leads *[]LeadReport,
	totalFlags *int,
	depth int,
	blockNum uint64,
) bool {
	// ---- 1. Depth / visited guard -----------------------------------
	if depth > maxTraversalDepth || visited[addr] {
		return false
	}
	visited[addr] = true

	// ---- 2. Proxy resolution ----------------------------------------
	impl := ResolveImplementation(ctx, client, addr)
	target := addr
	if impl != (common.Address{}) {
		target = impl
		log.Printf("scanner[proxy]: Resolved %s -> Impl %s", addr.Hex(), target.Hex())
	}

	// ---- 3. Bytecode fetch + role classification --------------------
	code, err := FetchBytecode(ctx, client, target)
	if err != nil || len(code) == 0 {
		log.Printf("scanner[source]: No bytecode at %s", target.Hex())
		return false
	}
	role, _ := ClassifyContract(ctx, code)

	// ---- 4. Dependency discovery ------------------------------------
	dummyUser := common.HexToAddress("0x1111111111111111111111111111111111111111")
	deps := DiscoverLinkedContracts(ctx, client, target, code, dummyUser)

	var topic0Hashes []common.Hash
	for _, sig := range FactoryEventSignatures {
		topic0Hashes = append(topic0Hashes, crypto.Keccak256Hash([]byte(sig)))
	}
	sqdDeps, err := ScanFactoryEventsSQD(ctx, target, topic0Hashes, blockNum)
	if err != nil {
		log.Printf("scanner[sqd]: Error fetching factory events: %v", err)
	} else {
		deps = append(deps, sqdDeps...)
	}

	// ---- 5. Bounded recursion ---------------------------------------
	children := 0
	for _, dep := range deps {
		if dep == (common.Address{}) || visited[dep] {
			continue
		}
		if children >= maxChildrenPerProtocol {
			log.Printf("scanner[cap]: Reached %d children for %s; stopping recursion", maxChildrenPerProtocol, target.Hex())
			break
		}
		scanTarget(ctx, client, rpcClient, rpcURL, exploiter, proto, dep,
			visited, flags, leads, totalFlags, depth+1, blockNum)
		children++
	}

	// ---- 6. Token short-circuit -------------------------------------
	if role == RoleToken {
		log.Printf("scanner[filter]: %s classified as RoleToken. Skipping.", target.Hex())
		return true
	}

	// ---- 7. Bytecode-level structural rules -------------------------
	selectors := ExtractSelectorsFromBytecode(code)
	bcFlags := RunBytecodeRules(selectors)
	structuralTaint := len(bcFlags) > 0

	var exploitContext string
	var provenVuln bool

	// ---- 8. Anvil economic proof gate -------------------------------
	exploitResult, err := exploiter.RunEconomicAttackHarness(ctx, target, role, deps)
	if err != nil {
		log.Printf("scanner[anvil]: Harness error: %v", err)
	} else if exploitResult != nil {
		if exploitResult.LeadOnly {
			*leads = append(*leads, LeadReport{
				RuleID:          "ANVIL_ORACLE_SPOT_DEPENDENT",
				Category:        "mixed-source",
				Severity:        "high",
				ContractAddress: target.Hex(),
				ContractRole:    string(role),
				Evidence:        exploitResult.Details,
			})
			log.Printf("scanner[anvil]: Structural lead recorded: %s", exploitResult.Details)
		} else {
			provenVuln = true
			exploitContext = fmt.Sprintf(
				"ANVIL ECONOMIC PROOF:\nType: %s\nTarget: %s\nProfit: %s wei\nDetails: %s\nTx: %s\n",
				exploitResult.AttackType, exploitResult.Target, exploitResult.ProfitWei.String(),
				exploitResult.Details, exploitResult.TxHash)
			log.Printf("scanner[anvil]: PROVEN EXPLOIT! Type: %s, Profit: %s",
				exploitResult.AttackType, exploitResult.ProfitWei.String())
		}
	}

	// ---- 9. Medusa invariant proof gate -----------------------------
	if !provenVuln && (role == RoleLending || role == RoleVault || role == RoleAMM) {
		log.Printf("scanner[fuzz]: Running Medusa invariants for %s (role: %s)", target.Hex(), role)
		fuzzResult, fuzzErr := RunMedusaFuzz(ctx, target, role, rpcURL, blockNum)
		switch {
		case fuzzResult != nil && fuzzResult.InvariantBroken && fuzzErr == nil:
			provenVuln = true
			exploitContext = fmt.Sprintf("MEDUSA FUZZ PROOF:\nInvariant: %s\nCounterexample: %s\n",
				fuzzResult.Invariant, fuzzResult.Counterexample)
			log.Printf("scanner[fuzz]: PROVEN via invariant break: %s", fuzzResult.Invariant)
		case fuzzResult != nil && fuzzResult.Skipped:
			log.Printf("scanner[fuzz]: Medusa skipped: %s", fuzzResult.SkipReason)
		case fuzzErr != nil:
			log.Printf("scanner[fuzz]: Medusa error: %v", fuzzErr)
		}
	}

	// ---- 10. Heimdall decompile (gated by proof OR taint) -----------
	shouldDecompile := provenVuln || structuralTaint
	var src string
	if shouldDecompile {
		log.Printf("scanner[heimdall]: Decompiling %s (Proven: %v, Tainted: %v)",
			target.Hex(), provenVuln, structuralTaint)
		decompiled, err := DecompileWithHeimdall(ctx, proto.Slug, target.Hex(), code, rpcURL, provenVuln, structuralTaint)
		if errors.Is(err, ErrDecompileSkipped) {
			log.Printf("scanner[heimdall]: Decompilation skipped (no proof, no taint)")
		} else if err != nil {
			log.Printf("scanner[heimdall]: Decompilation failed: %v", err)
		} else {
			src = decompiled
			log.Printf("scanner[heimdall]: Decompiled %s (%d bytes)", target.Hex(), len(src))
		}
	}

	// ---- 11. LLM root-cause analysis --------------------------------
	if provenVuln || structuralTaint {
		if src != "" {
			chunks := ChunkByFunction(src)
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
				if err != nil {
					log.Printf("scanner[llm]: ERROR: %v", err)
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
		}
	}

	// ---- 12. Regex tier over decompiled source (leads only) ---------
	// RunRegexScan produces heuristic hits (DIV_BEFORE_MUL, SPOT_NO_TWAP,
	// SELF_BALANCE, ORACLE_STALE, CHAINLINK_ROUND, LIQ_NO_HEALTH,
	// REENTRANCY). These are routed to Leads, not Findings — they have
	// not been proven economically. The LLM analysis above may have
	// already promoted some patterns to Findings via DYNAMIC_TRACE.
	if src != "" {
		regexFlags := RunRegexScan(src)
		for i := range regexFlags {
			regexFlags[i].ContractAddress = target.Hex()
			regexFlags[i].ContractRole = string(role)
			*leads = append(*leads, LeadReport{
				RuleID:          regexFlags[i].RuleID,
				Category:        regexFlags[i].Category,
				Severity:        regexFlags[i].Severity,
				ContractAddress: target.Hex(),
				ContractRole:    string(role),
				Evidence:        regexFlags[i].Snippet,
			})
			(*totalFlags)++
		}
	}

	// ---- 13. Bytecode leads -----------------------------------------
	// Structural selector combinations (BC_ORACLE_SPOT, BC_LENDING_UNCHECKED,
	// etc.) are unproven. They go to Leads, never Findings.
	for _, f := range bcFlags {
		(*totalFlags)++
		*leads = append(*leads, LeadReport{
			RuleID:          f.RuleID,
			Category:        f.Category,
			Severity:        f.Severity,
			ContractAddress: target.Hex(),
			ContractRole:    string(role),
			Evidence:        "bytecode selector combination",
		})
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
			if callErr == nil { return c, nil }
			lastErr = callErr
			c.Close()
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			if lastErr != nil { return nil, fmt.Errorf("%w (last: %v)", ctx.Err(), lastErr) }
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

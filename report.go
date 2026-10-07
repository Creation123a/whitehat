package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ---------- Public types ----------

type DependencyLevel string

const (
	DepNone      DependencyLevel = "NONE"
	DepSuspected DependencyLevel = "SUSPECTED"
	DepConfirmed DependencyLevel = "CONFIRMED"
)

// Finding is produced by analysis.go + simulation.go.
// Only gate-eligible findings live here. O-1..O-4 do NOT.
type Finding struct {
	Vault     common.Address
	Protocol  string   // "morpho" | "aave"
	Pool      common.Address
	Selectors []string // e.g. []{"getReserves()"} or []{"slot0()"}
	Verified  bool     // set by simulation.go
	Evidence  string   // set by simulation.go when Verified
}

// ProtocolReport is what lands in the JSON "protocols" array.
type ProtocolReport struct {
	Rank             int             `json:"rank"`
	Name             string          `json:"name"`
	Symbol           string          `json:"symbol,omitempty"`
	Address          common.Address  `json:"address"`
	AddressHash      string          `json:"address_hash"`
	Decimals         uint8           `json:"decimals,omitempty"`
	Protocol         string          `json:"protocol"`
	Pool             common.Address  `json:"pool"`
	Implementation   string          `json:"implementation,omitempty"`
	Selectors        []string        `json:"selectors"`
	SpotAMMDependent DependencyLevel `json:"spot_amm_dependent"`
	TVLUSD           float64         `json:"tvl_usd"`
	TVLSource        string          `json:"tvl_source"` // "totalAssets" | "balance_sum" | "none"
	Evidence         string          `json:"evidence,omitempty"`
	Remediation      string          `json:"remediation"`
}

type OperationalProperty struct {
	ID           string `json:"id"`
	Property     string `json:"property"`
	Present      bool   `json:"present"`
	Measures     string `json:"measures"`
	AuditFraming string `json:"audit_framing,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
	Source       string `json:"source"`        // "on-chain" | "declared" | "manual"
	GateEligible bool   `json:"gate_eligible"` // always false
}

type RunMetadata struct {
	SchemaVersion  string `json:"schema_version"`
	ChainID        int64  `json:"chain_id"`
	BlockNumber    uint64 `json:"block_number"`
	Timestamp      string `json:"timestamp"`
	CandidateCount int    `json:"candidate_count"`
	FalsePositives int    `json:"false_positive_count"`
}

type Report struct {
	Metadata              RunMetadata           `json:"metadata"`
	Protocols             []ProtocolReport      `json:"protocols"`
	OperationalProperties []OperationalProperty `json:"operational_properties"`
}

// ---------- Selectors ----------

var (
	selName        = []byte{0x06, 0xfd, 0xde, 0x03} // name()
	selSymbol      = []byte{0x95, 0xd8, 0x9b, 0x41} // symbol()
	selDecimals    = []byte{0x31, 0x3c, 0xe5, 0x67} // decimals()
	selTotalAssets = []byte{0x01, 0xe1, 0xd1, 0x14} // totalAssets()
	selAsset       = []byte{0x38, 0xd5, 0x2e, 0x0f} // asset()
	selBalanceOf   = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	selLatestRound = []byte{0xfe, 0xaf, 0x96, 0x8c} // latestRoundData()
)

// EIP-1967 implementation slot:
// keccak256("eip1967.proxy.implementation") - 1
var eip1967ImplSlot = common.HexToHash(
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
)

// ---------- Entry point ----------

// BuildReport enriches raw findings and assembles the final report.
// ops is the caller-supplied set of non-gate operational properties.
func BuildReport(
	ctx context.Context,
	client *ethclient.Client,
	meta RunMetadata,
	findings []Finding,
	ops []OperationalProperty,
) (*Report, error) {

	reports := make([]ProtocolReport, 0, len(findings))
	for _, f := range findings {
		pr, err := enrich(ctx, client, f)
		if err != nil {
			// Currently enrich never fails, but keep the path so future
			// metadata failures do not drop a finding.
			pr = ProtocolReport{
				Address:          f.Vault,
				AddressHash:      shortHash(f.Vault),
				Protocol:         f.Protocol,
				Pool:             f.Pool,
				Selectors:        f.Selectors,
				SpotAMMDependent: levelFor(f),
				TVLSource:        "none",
				Evidence:         f.Evidence,
				Remediation:      remediation(f.Protocol, f.Pool),
			}
		}
		reports = append(reports, pr)
	}

	// Primary sort: dependency level, then TVL descending.
	sortProtocols(reports)

	for i := range reports {
		reports[i].Rank = i + 1
	}

	meta.SchemaVersion = "1.1"
	meta.Timestamp = time.Now().UTC().Format(time.RFC3339)

	return &Report{
		Metadata:              meta,
		Protocols:             reports,
		OperationalProperties: ops,
	}, nil
}

// ---------- Enrichment ----------

// enrich never returns a non-nil error today. The error return is kept
// so future enrichment paths (e.g. ABI decoding of non-standard vaults)
// can fail without changing call sites.
func enrich(ctx context.Context, client *ethclient.Client, f Finding) (ProtocolReport, error) {
	pr := ProtocolReport{
		Address:          f.Vault,
		AddressHash:      shortHash(f.Vault),
		Protocol:         f.Protocol,
		Pool:             f.Pool,
		Selectors:        f.Selectors,
		SpotAMMDependent: levelFor(f),
		Evidence:         f.Evidence,
		Remediation:      remediation(f.Protocol, f.Pool),
	}

	// Max info: name / symbol / decimals / EIP-1967 impl.
	// Try the vault itself first; if it is a proxy with no metadata,
	// fall through to the implementation for name/symbol/decimals.
	if name, sym, dec, _ := readERC20Meta(ctx, client, f.Vault); name != "" || sym != "" || dec != 0 {
		pr.Name, pr.Symbol, pr.Decimals = name, sym, dec
	}

	if impl, ok := readEIP1967Impl(ctx, client, f.Vault); ok && impl != (common.Address{}) {
		pr.Implementation = impl.Hex()
		if pr.Name == "" {
			if name, sym, dec, _ := readERC20Meta(ctx, client, impl); name != "" || sym != "" || dec != 0 {
				pr.Name, pr.Symbol, pr.Decimals = name, sym, dec
			}
		}
	}

	if pr.Name == "" {
		if pr.Symbol != "" {
			pr.Name = pr.Symbol
		} else {
			pr.Name = "unnamed:" + pr.AddressHash
		}
	}

	tvl, src, err := computeTVL(ctx, client, f.Vault)
	if err == nil {
		pr.TVLUSD = tvl
		pr.TVLSource = src
	} else {
		pr.TVLSource = "none"
	}

	return pr, nil
}

func levelFor(f Finding) DependencyLevel {
	if f.Verified {
		return DepConfirmed
	}
	if len(f.Selectors) > 0 {
		return DepSuspected
	}
	return DepNone
}

func remediation(protocol string, pool common.Address) string {
	base := "integrate 30-min TWAP or Chainlink feed"
	if protocol == "" {
		protocol = "underlying"
	}
	return fmt.Sprintf("%s; %s pool at %s", base, protocol, pool.Hex())
}

// ---------- Metadata readers ----------

func readERC20Meta(
	ctx context.Context,
	client *ethclient.Client,
	addr common.Address,
) (name, symbol string, decimals uint8, ok bool) {
	if n, err := callString(ctx, client, addr, selName); err == nil {
		name = n
	}
	if s, err := callString(ctx, client, addr, selSymbol); err == nil {
		symbol = s
	}
	if d, err := callUint8(ctx, client, addr, selDecimals); err == nil {
		decimals = d
	}
	ok = name != "" || symbol != "" || decimals != 0
	return
}

func readEIP1967Impl(
	ctx context.Context,
	client *ethclient.Client,
	addr common.Address,
) (common.Address, bool) {
	raw, err := client.StorageAt(ctx, addr, eip1967ImplSlot, nil)
	if err != nil || len(raw) != 32 {
		return common.Address{}, false
	}
	h := common.BytesToHash(raw)
	if h == (common.Hash{}) {
		return common.Address{}, false
	}
	return common.BytesToAddress(h.Bytes()[12:]), true
}

// ---------- TVL ----------

func computeTVL(
	ctx context.Context,
	client *ethclient.Client,
	vault common.Address,
) (float64, string, error) {

	// (a) ERC-4626-style totalAssets().
	if ta, err := callBig(ctx, client, vault, selTotalAssets); err == nil && ta.Sign() > 0 {
		asset, err := callAddress(ctx, client, vault, selAsset)
		if err == nil {
			if usd, err := usdValue(ctx, client, asset, ta); err == nil {
				return usd, "totalAssets", nil
			}
		}
	}

	// (b) Fallback: sum balanceOf(vault) across the token registry.
	total := 0.0
	hits := 0
	for token := range TokenRegistry {
		bal, err := callBigWithArg(ctx, client, token, selBalanceOf, vault)
		if err != nil || bal.Sign() == 0 {
			continue
		}
		if usd, err := usdValue(ctx, client, token, bal); err == nil {
			total += usd
			hits++
		}
	}
	if hits == 0 {
		return 0, "none", fmt.Errorf("no priceable balances")
	}
	return total, "balance_sum", nil
}

// usdValue converts an amount of `token` to USD via its Chainlink feed.
func usdValue(
	ctx context.Context,
	client *ethclient.Client,
	token common.Address,
	amount *big.Int,
) (float64, error) {

	info, ok := TokenRegistry[token]
	if !ok || info.ChainlinkFeed == (common.Address{}) {
		return 0, fmt.Errorf("no feed for %s", token.Hex())
	}

	feedDec, err := callUint8(ctx, client, info.ChainlinkFeed, selDecimals)
	if err != nil {
		return 0, err
	}

	raw, err := client.CallContract(ctx, callMsgData(info.ChainlinkFeed, selLatestRound), nil)
	if err != nil {
		return 0, err
	}
	// latestRoundData() returns (uint80, int256, uint256, uint256, uint80)
	if len(raw) < 160 {
		return 0, fmt.Errorf("short latestRoundData response: %d bytes", len(raw))
	}
	answer := new(big.Int).SetBytes(raw[32:64])
	if answer.Sign() <= 0 {
		return 0, fmt.Errorf("non-positive chainlink answer")
	}

	price := new(big.Float).SetInt(answer)
	price.Quo(price, new(big.Float).SetInt(
		new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(feedDec)), nil)))

	amt := new(big.Float).SetInt(amount)
	amt.Quo(amt, new(big.Float).SetInt(
		new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(info.Decimals)), nil)))

	usd, _ := new(big.Float).Mul(price, amt).Float64()
	return usd, nil
}

// ---------- Low-level ABI helpers ----------

func callMsgData(to common.Address, selector []byte, args ...[]byte) ethereum.CallMsg {
	data := make([]byte, 0, 4+32*len(args))
	data = append(data, selector...)
	for _, a := range args {
		data = append(data, a...)
	}
	return ethereum.CallMsg{To: &to, Data: data}
}

func callBig(
	ctx context.Context, client *ethclient.Client,
	to common.Address, selector []byte,
) (*big.Int, error) {
	raw, err := client.CallContract(ctx, callMsgData(to, selector), nil)
	if err != nil {
		return nil, err
	}
	if len(raw) < 32 {
		return nil, fmt.Errorf("short response")
	}
	return new(big.Int).SetBytes(raw[:32]), nil
}

func callBigWithArg(
	ctx context.Context, client *ethclient.Client,
	to common.Address, selector []byte, arg common.Address,
) (*big.Int, error) {
	padded := common.LeftPadBytes(arg.Bytes(), 32)
	return callBig(ctx, client, to, append(append([]byte{}, selector...), padded...))
}

func callAddress(
	ctx context.Context, client *ethclient.Client,
	to common.Address, selector []byte,
) (common.Address, error) {
	raw, err := client.CallContract(ctx, callMsgData(to, selector), nil)
	if err != nil {
		return common.Address{}, err
	}
	if len(raw) < 32 {
		return common.Address{}, fmt.Errorf("short response")
	}
	return common.BytesToAddress(raw[12:32]), nil
}

func callUint8(
	ctx context.Context, client *ethclient.Client,
	to common.Address, selector []byte,
) (uint8, error) {
	v, err := callBig(ctx, client, to, selector)
	if err != nil {
		return 0, err
	}
	return uint8(v.Uint64()), nil
}

// callString decodes either a dynamic ABI string or a bytes32 (MKR-style).
func callString(
	ctx context.Context, client *ethclient.Client,
	to common.Address, selector []byte,
) (string, error) {
	raw, err := client.CallContract(ctx, callMsgData(to, selector), nil)
	if err != nil {
		return "", err
	}
	if len(raw) == 32 {
		// bytes32-style
		return strings.TrimRight(string(raw), "\x00"), nil
	}
	if len(raw) < 64 {
		return "", fmt.Errorf("short string response")
	}
	off := new(big.Int).SetBytes(raw[:32]).Uint64()
	if uint64(len(raw)) < off+32 {
		return "", fmt.Errorf("bad string offset")
	}
	l := new(big.Int).SetBytes(raw[off : off+32]).Uint64()
	if uint64(len(raw)) < off+32+l {
		return "", fmt.Errorf("bad string length")
	}
	return string(raw[off+32 : off+32+l]), nil
}

func shortHash(a common.Address) string {
	h := a.Hex()
	return h[:8] + "..." + h[len(h)-4:]
}

// ---------- Sorting ----------

var depOrder = map[DependencyLevel]int{
	DepConfirmed: 0,
	DepSuspected: 1,
	DepNone:      2,
}

func sortProtocols(rs []ProtocolReport) {
	sort.SliceStable(rs, func(i, j int) bool {
		oi, oj := depOrder[rs[i].SpotAMMDependent], depOrder[rs[j].SpotAMMDependent]
		if oi != oj {
			return oi < oj
		}
		return rs[i].TVLUSD > rs[j].TVLUSD
	})
}

// ---------- Rendering ----------

func RenderText(w io.Writer, r *Report) {
	fmt.Fprintf(w, "=== SPOT-AMM DEPENDENCY SCAN ===\n")
	fmt.Fprintf(w, "Chain %d  Block %d  %s\n",
		r.Metadata.ChainID, r.Metadata.BlockNumber, r.Metadata.Timestamp)
	fmt.Fprintf(w, "Candidates: %d   False positives: %d\n\n",
		r.Metadata.CandidateCount, r.Metadata.FalsePositives)

	fmt.Fprintln(w, "--- PROTOCOLS (sorted by spot-AMM dependency) ---")
	for _, p := range r.Protocols {
		fmt.Fprintf(w, "\n[%d] %-9s  %s\n", p.Rank, p.SpotAMMDependent, p.Name)
		if p.Symbol != "" {
			fmt.Fprintf(w, "     Symbol:     %s\n", p.Symbol)
		}
		fmt.Fprintf(w, "     Address:    %s\n", p.AddressHash)
		fmt.Fprintf(w, "     Protocol:   %s\n", p.Protocol)
		fmt.Fprintf(w, "     Pool:       %s\n", p.Pool.Hex())
		if p.Implementation != "" {
			fmt.Fprintf(w, "     Impl:       %s\n", p.Implementation)
		}
		fmt.Fprintf(w, "     Selectors:  %s\n", strings.Join(p.Selectors, ", "))
		if p.TVLSource == "none" {
			fmt.Fprintf(w, "     TVL:        n/a\n")
		} else {
			fmt.Fprintf(w, "     TVL:        $%.2f  (%s)\n", p.TVLUSD, p.TVLSource)
		}
		if p.Evidence != "" {
			fmt.Fprintf(w, "     Evidence:   %s\n", p.Evidence)
		}
		fmt.Fprintf(w, "     Remediate:  %s\n", p.Remediation)
	}

	if len(r.OperationalProperties) > 0 {
		fmt.Fprintln(w, "\n--- OPERATIONAL PROPERTIES (non-gate; context only) ---")
		for _, o := range r.OperationalProperties {
			state := "absent"
			if o.Present {
				state = "present"
			}
			fmt.Fprintf(w, "\n%s  %-28s [%s]\n", o.ID, o.Property, state)
			fmt.Fprintf(w, "     Measures:  %s\n", o.Measures)
			if o.AuditFraming != "" {
				fmt.Fprintf(w, "     Framing:   %s\n", o.AuditFraming)
			}
			if o.Remediation != "" {
				fmt.Fprintf(w, "     Remediate: %s\n", o.Remediation)
			}
			fmt.Fprintf(w, "     Source:    %s (gate_eligible=false)\n", o.Source)
		}
	}
}

func RenderJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ---------- O-1..O-4 seed ----------

// DefaultOperationalProperties returns the four non-gate rows with fixed
// framing text. Caller toggles Present from CLI/sidecar/env.
func DefaultOperationalProperties(present map[string]bool) []OperationalProperty {
	rows := []OperationalProperty{
		{
			ID: "O-1", Property: "Public RPC only",
			Measures:     "Monitoring posture",
			AuditFraming: "No evidence of monitoring infrastructure; mean time to detection may exceed block finality (soft inference)",
			Remediation:  "Deploy dedicated alerting",
			Source:       "declared",
		},
		{
			ID: "O-2", Property: "Anonymous team",
			Measures: "Attribution difficulty",
			Source:   "declared",
		},
		{
			ID: "O-3", Property: "No legal entity",
			Measures: "Post-incident recovery capability",
			Source:   "declared",
		},
		{
			ID: "O-4", Property: "Tracking obsolete",
			Measures: "Attribution difficulty",
			Source:   "declared",
		},
	}
	for i := range rows {
		if v, ok := present[rows[i].ID]; ok {
			rows[i].Present = v
		}
		rows[i].GateEligible = false
	}
	return rows
}

// ---------- CLI helper ----------

// WriteReport dispatches text or JSON and returns exit code 0/1.
func WriteReport(path string, format string, r *Report) int {
	var w io.Writer = os.Stdout
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report: cannot create %s: %v\n", path, err)
			return 1
		}
		defer f.Close()
		w = f
	}
	if format == "json" {
		if err := RenderJSON(w, r); err != nil {
			fmt.Fprintf(os.Stderr, "report: json encode: %v\n", err)
			return 1
		}
	} else {
		RenderText(w, r)
	}
	return 0
}

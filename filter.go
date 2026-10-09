package main

import "sort"

// FilterMarketsByProtocolCount drops markets that do not have at
// least minProtocols distinct protocols attached. In the v6.0
// pipeline this is OFF by default (min-protocols=0) because
// triage runs first and markets with zero known protocols are
// still valid findings.
func FilterMarketsByProtocolCount(
	in []MarketWithProtocols,
	minProtocols int,
) []MarketWithProtocols {

	var out []MarketWithProtocols
	for _, mp := range in {
		if len(mp.Protocols) >= minProtocols {
			out = append(out, mp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Market.SupplyUSD > out[j].Market.SupplyUSD
	})
	return out
}

// FilterProtocolsByTVL removes dust protocols from each market's
// protocol list. A protocol survives if either:
//   - its own TotalAssetsUSD >= minTVL, OR
//   - its allocation to this specific market >= minTVL.
//
// Markets with no protocols after filtering are still kept: a
// vulnerable oracle with no known protocol exposure is still a
// finding (the exposure may be undiscovered).
//
// MarketID comparisons use normalizeMarketID on both sides, since
// the Morpho API returns mixed casing across endpoints.
func FilterProtocolsByTVL(
	in []MarketWithProtocols,
	minTVL float64,
) []MarketWithProtocols {

	out := make([]MarketWithProtocols, 0, len(in))
	for _, mp := range in {
		marketKey := normalizeMarketID(mp.Market.MarketID)
		var kept []Protocol
		for _, p := range mp.Protocols {
			if p.TotalAssetsUSD >= minTVL {
				kept = append(kept, p)
				continue
			}
			for _, a := range p.Allocations {
				if normalizeMarketID(a.MarketID) == marketKey &&
					a.SupplyUSD >= minTVL {
					kept = append(kept, p)
					break
				}
			}
		}
		mp.Protocols = kept
		out = append(out, mp)
	}
	return out
}

// FilterMarketsByOracleVulnerability keeps only markets whose
// oracle triage flagged a spot-AMM read.
func FilterMarketsByOracleVulnerability(
	in []MarketWithProtocols,
	vulnerable map[string]bool,
) []MarketWithProtocols {

	var out []MarketWithProtocols
	for _, mp := range in {
		if vulnerable[mp.Market.MarketID] {
			out = append(out, mp)
		}
	}
	return out
}

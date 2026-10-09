package main

import "sort"

// FilterMarketsByProtocolCount drops markets that do not have at
// least MinProtocolsPerMarket distinct protocols attached.
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
// The second clause matters for large MetaMorpho vaults that only
// route a small slice into a given market: the vault is not dust,
// and its exposure to this market is what we are checking.
func FilterProtocolsByTVL(
	in []MarketWithProtocols,
	minTVL float64,
) []MarketWithProtocols {

	var out []MarketWithProtocols
	for _, mp := range in {
		var kept []Protocol
		for _, p := range mp.Protocols {
			if p.TotalAssetsUSD >= minTVL {
				kept = append(kept, p)
				continue
			}
			// Check the per-market allocation.
			for _, a := range p.Allocations {
				if a.MarketID == mp.Market.MarketID && a.SupplyUSD >= minTVL {
					kept = append(kept, p)
					break
				}
			}
		}
		if len(kept) == 0 {
			continue
		}
		mp.Protocols = kept
		out = append(out, mp)
	}
	return out
}

// FilterMarketsByOracleVulnerability keeps only markets whose
// oracle triage flagged a spot-AMM read. This is applied after
// TriageOracles. Protocols on non-vulnerable markets are dropped
// from the pipeline entirely.
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

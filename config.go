package main

import (
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const (
	DefiLlamaProtocolsURL = "https://api.llama.fi/protocols"
	DefiLlamaBaseChain    = "Base"

	EIP1967ImplementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)

// =============================================================
// v11.0 Pipeline Constants
// =============================================================

const (
	// maxTraversalDepth limits how deep the scanner will recursively
	// probe linked contracts (e.g. Market -> Oracle -> Pool -> Factory).
	maxTraversalDepth = 5

	// maxDecompilesPerProtocol prevents spending hours decompiling
	// every single proxy implementation if a protocol has hundreds.
	maxDecompilesPerProtocol = 30
)

// =============================================================
// Protocol Registry
// =============================================================

var BaseProtocolRegistry = map[string][]common.Address{
	// Lending
	"native-credit-pool": {
		common.HexToAddress("0x74a4Cd023e5AfB88369E3f22b02440F2614a1367"),
	},
	"exactly": {
		common.HexToAddress("0x0Aeb0BCB919858C0a4dceC3EeD879985034A597c"),
		common.HexToAddress("0x85c21fA8AeE39891E115E2b28c3dB2dE5B0AaF4f"),
	},
	"morpho-midnight": {
		common.HexToAddress("0xAdedD8ab6dE832766Fedf0FaC4992E5C4D3EA18A"),
	},
	"revert-lend": {
		common.HexToAddress("0x36AEAe0E411a1E28372e0d66f02E57744EbE7599"),
	},
	"seamless-v2": {
		common.HexToAddress("0x8F44Fd754285aa6A2b8B9B97739B79746e0475a7"),
	},
	"extra-finance-xlend": {
		common.HexToAddress("0xbb505c54d71e9e599cb8435b4f0ceec05fc71cbd"),
		common.HexToAddress("0xf9cfb8a62f50e10adde5aa888b44cf01c5957055"),
	},
	"surge-credit": {
		common.HexToAddress("0xEE755F1BbcbF6e3260469D0f473522d71d3bdDda"),
	},
	"mortgagefi": {
		common.HexToAddress("0x233c539b5eb3d349c85a15de0ab5458456bb358e"),
	},
	"teller": {
		common.HexToAddress("0x48EE9c344d5C6d202F4b3225A694957a3412008d"),
	},
	"tarot": {
		common.HexToAddress("0xf544251d25f3d243a36b07e7e7962a678f952691"),
	},
	"impermax-v2": {
		common.HexToAddress("0x74497E4efe07E7A71d1d857C6b68bD2115EB948F"),
	},
	"seamless-v1": {
		common.HexToAddress("0x59a11C2f543790b8ce1A2DC46C4ad08A4536BdC8"),
		common.HexToAddress("0x8f44fd754285aa6A2b8B9B97739B79746e0475a7"),
	},
	"radiant-v2": {
		common.HexToAddress("0x30798cFe2CCa822321ceed7e6085e633aAbC492F"),
		common.HexToAddress("0x5D64926bEF21BD772e7d6F89AED16d8c1A93dD66"),
	},
	"ripe-protocol": {
		common.HexToAddress("0x6162df1b329E157479F8f1407E888260E0EC3d2b"),
	},
	"astaria-v2": {
		common.HexToAddress("0x0000000000A6F0986c92cf1EC4d2e77aFBE1466D"),
		common.HexToAddress("0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC"),
	},
	"sonne-finance": {
		common.HexToAddress("0x60CF091cD3f50420d50fD7f707414d0DF4751C58"),
	},

	// Yield
	"spark-savings": {
		common.HexToAddress("0x5875eEE11Cf8398102FdAd704C9E96607675467a"),
		common.HexToAddress("0x3128a0F7f0ea68E7B7c9B00AFa7E41045828e858"),
	},
	"pendle-v2": {
		common.HexToAddress("0x888888888889758F76e7103c6CbF23ABbF58F946"),
	},
	"stake-dao-yield": {
		common.HexToAddress("0xB0552b6860CE5C0202976Db056b5e3Cc4f9CC765"),
		common.HexToAddress("0x5DA07af8913A4EAf09E5F569c20138b658906c17"),
		common.HexToAddress("0x32dA29D7F3aD8cF157C6427CecFD3f0665042A37"),
	},
	"infinifi": {
		common.HexToAddress("0x4cE95DaF47410f21008fDa15D27c801f462Fb872"),
	},
	"autofinance": {
		common.HexToAddress("0xC7d7F434C015F2A7E77dF9763ADE300F2171a05a"),
	},
	"royco-v2": {
		common.HexToAddress("0xaf55a0c251690d9322b5F94b7e50EE895750262c"),
		common.HexToAddress("0xaAAaaAAAaE46cA12Bf3810DF8C13c5E8A4400812"),
		common.HexToAddress("0x387e025306cb1C41fe7AB752D9C04607E03Bb8CE"),
		common.HexToAddress("0x783251f103555068c1e9d755f69458f39ed937c0"),
	},
	"spectra-v2": {
		common.HexToAddress("0x64fcc3a02eeeba05ef701b7eed066c6ebd5d4e51"),
	},
	"toros": {
		common.HexToAddress("0x633659223ED6f082e6efbB9C49c2AbA6C4d3Ea87"),
	},
	"woofi-earn": {
		common.HexToAddress("0x44dF096D2600C6a6db77899dB3DE3AeCff746cb8"),
		common.HexToAddress("0x73Bd3C7e44E1c228713A24448e9B7250391ACa15"),
		common.HexToAddress("0xa1bb8a8ED84A37a8c93a10Df5153E612f58e34E5"),
	},
	"ledgity-yield": {
		common.HexToAddress("0x9161B1E37A684DF2CcCf039e15948F6Da94A2cF0"),
		common.HexToAddress("0x3C769d0e8D21d380228dFB7918c6933bb6ecB6D4"),
	},
	"peapods-finance": {
		common.HexToAddress("0x02f92800F57BCD74066F5709F1Daa1A4302Df875"),
		common.HexToAddress("0x21FE3e26E824783cA7E374355A8D30Ae8BBf6E37"),
	},
	"royco-v1": {
		common.HexToAddress("0x783251f103555068c1E9D755f69458f39eD937c0"),
	},
	"zircuit-finance": {
		common.HexToAddress("0x0792C46723d479D4C29De5D78D93C0146EdF3f5B"),
		common.HexToAddress("0xfd418e42783382e86ae91e445406600ba144d162"),
	},
	"sprinter": {
		common.HexToAddress("0x479D158959B59328E89f0fbF7DfeBb198c313C21"),
	},
	"velvet-v3": {
		common.HexToAddress("0xbF927b841994731C573BDF09ceB0c6B0Aa887cDd"),
		common.HexToAddress("0x6b0f53cbd9272d8117e9535fe25371dedf39a1be"),
	},
	"surf-liquid": {
		common.HexToAddress("0xcDca2EaAe4a8a6B83D7a3589946C2301040dAFbf"),
	},
	"gilder": {
		common.HexToAddress("0x9C907FdFDda7BC57e2F05D7CefbB198c313CdE1c"),
	},
	"gammaswap-yield-tokens": {
		common.HexToAddress("0xc4d44c155f95FD4E94600d191a4a01bb571dF7DF"),
		common.HexToAddress("0xaeAAc90117fb85a7DC961522DdFe96ABB358445B"),
	},

	// Yield Aggregator
	"yearn-finance": {
		common.HexToAddress("0x775F09d6f3c8D2182DFA8bce8628acf51105653c"),
		common.HexToAddress("0xea3481244024E2321cc13AcAa80df1050f1fD456"),
		common.HexToAddress("0x1f399808fE52d0E960CAB84b6b54d5707ab27c8a"),
		common.HexToAddress("0x1e9eB053228B1156831759401dE0E115356b8671"),
	},
	"vesper": {
		common.HexToAddress("0x4b777b92e6308e2c01022c96cea4acadd51f3ba3"),
	},
	"superform": {
		common.HexToAddress("0x5b2193fDc451C1f847bE09CA9d13A4Bf60f8c86B"),
	},
	"yieldfi": {
		common.HexToAddress("0x895e15020c3f52ddd4d8e9514eb83c39f53b1579"),
		common.HexToAddress("0x8c93a6752Bfe29FDA26EbA8df4390c642e6A7f90"),
	},
	"odyssey-finance": {
		common.HexToAddress("0xeE156D8ea7b96a5524CcC3CF9283ab85E80E9534"),
	},
	"bim-yield": {
		common.HexToAddress("0x555FFF48549C1A25a723Bd8e7eD10870D82E8379"),
	},
	"stratex": {
		common.HexToAddress("0xe5f2fe713CDB192C85e67A912Ff8891b4E636614"),
		common.HexToAddress("0x9213d24f617dE982dB528c95A701eD1b2AF29cB2"),
		common.HexToAddress("0xae35ff1bc4fbb45aaeef9768a3d9610786cac98b"),
	},
	"frgmnt": {
		common.HexToAddress("0xeB82611A2B2dC9FBEAF5903d5decDf801765B759"),
	},
	"autopilot": {
		common.HexToAddress("0x31A421271414641cb5063B71594b642D2666dB6B"),
		common.HexToAddress("0xEd5d22F133bB20deE41629b84348F60925E8bDE0"),
	},
	"maxapy": {
		common.HexToAddress("0x7a63e8FC1d0A5E9BE52f05817E8C49D9e2d6efAe"),
		common.HexToAddress("0x1c117e6cC629C414377Fdbb427db329fD0821F9a"),
		common.HexToAddress("0x9FDfd9c1e23D687F7a154610816de6E47Fb4FC64"),
	},

	// CDP
	"btcfi-cdp": {
		common.HexToAddress("0xe4b20925D9E9a62F1E492e15a81dC0de62804dd4"),
	},
	"qidao": {
		common.HexToAddress("0xbf1aeA8670D2528E08334083616dD9C5F3B087aE"),
	},
	"parallel-protocol-v3": {
		common.HexToAddress("0x76A9A0062ec6712b99B4f63bD2b4270185759dd5"),
		common.HexToAddress("0x4Dde0e308CFB60515218C6ad2DF1134Fc48531FC"),
		common.HexToAddress("0x08417cdb7F52a5021bB4eb6E0deAf3f295c3f182"),
		common.HexToAddress("0xfD28f108e95f4D41daAE9dbfFf707D677985998E"),
	},
	"base-dollar": {
		common.HexToAddress("0x252d36f435582ecb01686448d21e8c9ea0b2ca65"),
	},
	"vaultedge": {
		common.HexToAddress("0x89AbeeE01B8c544cc7516B1e44102a063D79cd4D"),
	},

	// Basis Trading
	"sosovalue-basis": {
		common.HexToAddress("0x624e2e7fDc8903165F64891672267AB0FCB98831"),
	},

	// Derivatives
	"apex-omni": {
		common.HexToAddress("0xeE7981C4642dE8d19AeD11dA3bac59277DfD59D7"),
	},
	"gains-network": {
		common.HexToAddress("0x6cD5aC19a07518A8092eEFfDA4f1174C72704eeb"),
	},
	"synfutures-v3": {
		common.HexToAddress("0x4f090d817fd83753988a7b0c1d76f170f8461be8"),
		common.HexToAddress("0x2c24497d4086490e7ead87cc12597fb50c2e6ed6"),
	},
	"symmio": {
		common.HexToAddress("0x1c03B6480a4efC2d4123ba90d7857f0e1878B780"),
	},
	"kiloex": {
		common.HexToAddress("0x22c40b883b5976f13c78ee45ead6b0cdc192dae5"),
	},
	"bmx-freestyle": {
		common.HexToAddress("0x1c03B6480a4efC2d4123ba90d7857f0e1878B780"),
		common.HexToAddress("0x548f93779fbc992010c07467cbaf329dd5f059b7"),
	},
	"ipor-derivatives": {
		common.HexToAddress("0x41883F367ab187B1C676A4A4767758916A6a01Fa"),
	},
	"rollx": {
		common.HexToAddress("0xab6363da0c80cef3ae105bd6241e30872355d021"),
	},
	"bmx-classic-perps": {
		common.HexToAddress("0x9a99a30e4740d496484f04ef4a097d6ce584fb46"),
		common.HexToAddress("0x859bC5FE903dFe749fE3331512Ff7297D2E924f3"),
	},
	"infinitypools": {
		common.HexToAddress("0x86342D7bBe93cB640A6c57d4781f04d93a695f08"),
	},
	"domination-finance": {
		common.HexToAddress("0xA194082Aabb75Dd1Ca9Dc1BA573A5528BeB8c2Fb"),
	},
	"javsphere": {
		common.HexToAddress("0xEdC6136B26A0E341103f75e48936900Fe39aF2C6"),
	},

	// Liquid Staking
	"ether.fi-stake": {
		common.HexToAddress("0x1a44076050125825900e736c501f859c50fE728c"),
	},
	"origin-ether": {
		common.HexToAddress("0xD8724322f44E5c58D7A815F542036fb17DbbF839"),
		common.HexToAddress("0xDBFeFD2e8460a6Ee4955A68582F85708BAEA60A3"),
	},
	"iaero-protocol": {
		common.HexToAddress("0x81034Fb34009115F215f5d5F564AAc9FfA46a1Dc"),
	},
	"diem-relay": {
		common.HexToAddress("0x8065228a8156590A8BFca30678394e9db91f80Ee"),
		common.HexToAddress("0x981A7bF20D62d8076A9A0062ec6712b99B4f63bD"),
	},
	"bakerfi": {
		common.HexToAddress("0x20Ff0d43681e6bE06f89015E55fB909338A21cbF"),
	},

	// RWA
	"re": {
		common.HexToAddress("0x7D214438D0F27AfCcC23B3d1e1a53906aCE5CFEa"),
		common.HexToAddress("0xaDC4794909605570D4C43040EB2bd5c0871feDDA"),
	},
	"anemoy-capital": {
		common.HexToAddress("0x8c213ee79581ff4984583c6a801e5263418c4b86"),
	},
	"brickken": {
		common.HexToAddress("0xFc209EeBA3D744aA741cc5C2A73Ebf9C977B5F82"),
	},
	"realtyx": {
		common.HexToAddress("0x5b1e769e74fd7e532a48261ab42ee906f0090556"),
	},
	"8lends": {
		common.HexToAddress("0x55F9C8992fc4AbCE5ACa585bf8F18284a2379D4C"),
	},
}

var TargetCategories = map[string]bool{
	"Lending":           true,
	"Yield":             true,
	"Yield Aggregator":  true,
	"CDP":               true,
	"Leveraged Farming": true,
	"Dexs":              true,
	"Basis Trading":     true,
	"Derivatives":       true,
	"Farm":              true,
	"Liquid Staking":    true,
	"RWA":               true,
}

// =============================================================
// Scanner Parameters
// =============================================================

const (
	MinTVLUSD = 50_000
	MaxTVLUSD = 10_000_000
)

const (
	requiredChainID = 31337
	anvilReadyMax   = 60 * time.Second
	anvilPollEvery  = 250 * time.Millisecond
)

// =============================================================
// Stablecoin Helpers
// =============================================================

func isStableAsset(a AssetInfo) bool {
	if a.Address != "" {
		addr := common.HexToAddress(a.Address)
		if stableAddresses[addr] {
			return true
		}
	}
	return stableSymbols[normalizeStableSymbol(a.Symbol)]
}

func normalizeStableSymbol(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	for _, suffix := range []string{".E", ".B", "+", "-"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

var stableAddresses = map[common.Address]bool{
	common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"): true,
	common.HexToAddress("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"): true,
	common.HexToAddress("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"): true,
	common.HexToAddress("0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42"): true,
	common.HexToAddress("0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"): true,
	common.HexToAddress("0x417Ac0e078398C154EdFadD9Ef675d30Be60Af93"): true,
	common.HexToAddress("0x6Bb7a212910682DCFdbd5BCBb3e28FB4E8da10Ee"): true,
}

var stableSymbols = map[string]bool{
	"USDC": true, "USDT": true, "DAI": true, "USDBC": true,
	"EURC": true, "CUSDO": true, "USDE": true, "SUSDE": true,
	"USDS": true, "SUSDS": true, "CRVUSD": true, "GHO": true,
}

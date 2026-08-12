**Intern** @Billyone9

**Protocol:** Solidity-3

**weeks** Weeks 2

# CRITICAL ISSUES

---

## Issue Title [C1]

`AdminFacet` critical configuration functions are unprotected `onlyOwner` modifier is defined but never applied,
allowing any caller to reconfigure the protocol

---

## Summary

`AdminFacet` defines an `onlyOwner` modifier that checks against the Diamond's contract owner, but fails to apply it to
any of its four mutating functions: `setCTokenAddress`, `setAavePoolAddress`, `setRequestThreshold`, and `initMappings`.
Any externally owned account or contract can call these functions without restriction, enabling a complete takeover of
the protocol's configuration including redirecting all token flows to attacker-controlled contracts.

---

## Vulnerability Details

`AdminFacet` correctly defines the access control modifier:

```solidity
modifier onlyOwner() {
    require(
        msg.sender == LibDiamond.diamondStorage().contractOwner,
        "AdminFacet: Not owner"
    );
    _;
}
```

However, none of the four state-mutating functions in the contract apply it:

```solidity
// Anyone can call — no onlyOwner
function setCTokenAddress(address[] memory tokens, address[] memory cTokens) external {
    LibAdapterStorage.Storage storage s = LibAdapterStorage.getStorage();
    for (uint256 i = 0; i < tokens.length; i++) {
        s.tokenAddressToCTokenAddress[tokens[i]] = cTokens[i];
        s.cTokenAddressToTokenAddress[cTokens[i]] = tokens[i];
    }
}

// Anyone can call — no onlyOwner
function setAavePoolAddress(address pool, address poolDataProvider) external {
    LibAdapterStorage.Storage storage s = LibAdapterStorage.getStorage();
    s.aavePool = IPool(pool);
    s.aaveDataProvider = IPoolDataProvider(poolDataProvider);
}

// Anyone can call — no onlyOwner
function setRequestThreshold(uint8 threshold) external {
    LibAdapterStorage.Storage storage s = LibAdapterStorage.getStorage();
    s.REQUEST_THRESHOLD = threshold;
}

// Anyone can call — no onlyOwner
function initMappings(address user, address[] memory tokens) external {
    ...
}
```

The impact of each unprotected function, ranked by severity:

**`setCTokenAddress` — highest impact.** This function controls the bidirectional mapping between underlying ERC20
tokens (e.g., USDC) and their confidential wrappers (cUSDC). Every library function (`LibSupplyRequest`,
`LibBorrowRequest`, `LibWithdrawRequest`, `LibRepayRequest`) resolves the cToken to interact with via
`s.tokenAddressToCTokenAddress[asset]`. An attacker can remap a legitimate asset to a malicious cToken contract they
control. All subsequent supply, borrow, withdraw, and repay operations for that asset will then interact with the
attacker's contract instead of the legitimate cToken enabling silent fund theft at every user interaction.

**`setAavePoolAddress` — highest impact.** This replaces the `IPool` and `IPoolDataProvider` references that all four
operation flows use for `supply`, `borrow`, `withdraw`, and `repay` calls. Replacing this with a malicious contract
causes all user funds flowing through `finalizeSupplyRequests`, `finalizeBorrowRequests`, `callbackWithdrawRequest`, and
`finalizeRepayRequests` to be routed to an attacker-controlled address. LTV values returned by a fake
`IPoolDataProvider` can also be manipulated to set every user's `userMaxBorrowablePerAsset` to an arbitrary value.

**`setRequestThreshold` — medium impact.** Setting `REQUEST_THRESHOLD` to `1` forces every single-user request to be
immediately batched and decrypted by the Gateway, eliminating the k-anonymity privacy guarantee that is core to the
protocol's design. Setting it to `255` permanently stalls all operations, as batches can never fill.

**`initMappings` — medium impact.** Can be called by an attacker for any user address and any token list, initializing
or overwriting a target user's encrypted `scaledBalances`, `scaledDebts`, and `userMaxBorrowablePerAsset` to zero. This
erases any existing FHE state for that user, effectively wiping their tracked collateral and debt positions within the
adapter.

---

## Steps to Reproduce

1. Deploy the Diamond with its facets on a testnet (or fork of mainnet with Aave V3 deployed).

2. Deploy a malicious contract `MaliciousCToken` that implements the `ConfidentialERC20Wrapped` interface but redirects
   all `transferFrom` calls to the attacker's wallet.

3. From **any EOA** (not the owner), call `AdminFacet.setCTokenAddress` with the legitimate USDC address and the
   `MaliciousCToken` address:

   ```solidity
   adminFacet.setCTokenAddress(
       [USDC_ADDRESS],
       [MALICIOUS_CTOKEN_ADDRESS]
   );
   ```

4. Any user who now calls `SupplyFacet.supplyRequest(USDC, encAmount, 0)` will have their cTokens pulled into
   `MaliciousCToken.transferFrom`, routing funds to the attacker.

5. Confirm the owner's address was never involved at any point in steps 2–4.

---

## Recommended Fix

Apply the `onlyOwner` modifier to all four mutating functions in `AdminFacet`:

```solidity
function setCTokenAddress(
    address[] memory tokens,
    address[] memory cTokens
) external onlyOwner {
    ...
}

function setAavePoolAddress(
    address pool,
    address poolDataProvider
) external onlyOwner {
    ...
}

function setRequestThreshold(uint8 threshold) external onlyOwner {
    ...
}

function initMappings(
    address user,
    address[] memory tokens
) external onlyOwner {
    ...
}
```

---

## Issue Title [C2]

`LibWithdrawRequest._processStateUpdates()` subtracts raw cToken units from `scaledBalances` which stores Aave-scaled
balance units a denomination mismatch that permanently corrupts per-user collateral accounting

---

## Summary

`LibSupplyRequest.finalizeSupplyRequests()` correctly converts a user's cToken input amount into Aave-scaled balance
units using a measured `multiplier` before crediting `scaledBalances[user][asset]`.
`LibWithdrawRequest.finalizeWithdrawRequest()` subtracts the user's raw cToken request amount directly from the same
`scaledBalances` field without any unit conversion. Because Aave's liquidity index grows continuously with interest
accrual, the two denominations diverge from the moment of first supply. Every withdrawal subtracts a slightly smaller
number than was added, causing `scaledBalances` to drift upward monotonically. The inflated balance feeds directly into
`userMaxBorrowablePerAsset`, allowing users to borrow more than their actual collateral permits. The error compounds
with every supply-withdraw cycle.

---

## Vulnerability Details

### Background: What `scaledBalances` Stores

When Aave executes a `supply`, it issues aTokens to the supplier. Internally Aave tracks these as **scaled balances**:
`scaledBalance = amount / liquidityIndex`. The liquidity index starts at `1e27` (ray) and grows as interest accrues. The
actual redeemable amount at any time is `scaledBalance * currentLiquidityIndex`. The Diamond holds aTokens on behalf of
all users and mirrors each user's share in `scaledBalances[user][asset]`.

### How Supply Writes to `scaledBalances` — Correct

`finalizeSupplyRequests` measures the actual change in the Diamond's aToken scaled balance before and after calling
`aavePool.supply`, then computes a `multiplier` that converts cToken input units to Aave scaled balance units:

```solidity
// LibSupplyRequest.finalizeSupplyRequests()
uint256 beforeScaledBalance = IScaledBalanceToken(aToken).scaledBalanceOf(address(this));
s.aavePool.supply(asset, amount, address(this), requests[0].referralCode);
uint256 afterScaledBalance  = IScaledBalanceToken(aToken).scaledBalanceOf(address(this));

uint256 difference = afterScaledBalance - beforeScaledBalance; // in Aave scaled units
uint256 multiplier = difference / (amount / (10 ** 6));        // scaled units per cToken unit
```

It then credits each user's share using the multiplier:

```solidity
// LibSupplyRequest._processStateUpdates()
euint64 newBalance = TFHE.add(
    s.scaledBalances[sender][asset],
    TFHE.div(TFHE.mul(amount, uint64(multiplier)), 1e6) // converted to Aave scaled units
);
s.scaledBalances[sender][asset] = newBalance;
```

After this write, `scaledBalances[user][asset]` is denominated in **Aave scaled balance units**.

### How Withdraw Writes to `scaledBalances` Incorrect

`finalizeWithdrawRequest` calls `_processStateUpdates` which subtracts the raw user-requested amount — the same
`euint64` that was validated against `withdrawableScaledBalance` but never converted — directly from `scaledBalances`:

```solidity
// LibWithdrawRequest._processStateUpdates()
s.scaledBalances[requests[i].sender][asset] = TFHE.sub(
    s.scaledBalances[requests[i].sender][asset],
    requests[i].amount  // raw cToken units, NOT Aave scaled units
);
```

`requests[i].amount` is the `euint64` captured at `withdrawRequest()` time:

```solidity
// LibWithdrawRequest.withdrawRequest()
euint64 safeAmount = TFHE.select(
    TFHE.le(amount, withdrawableScaledBalance),
    amount,              // ← user's input in cToken units
    TFHE.asEuint64(0)
);
s.withdrawRequests.push(WithdrawRequestData({ ..., amount: safeAmount, ... }));
```

The comparison `TFHE.le(amount, withdrawableScaledBalance)` does check the amount against
`scaledBalances - scaledDebts`, but the comparison result (a clamped amount) is still in the user's original input
denomination, not in Aave scaled balance units. No conversion is ever applied.

### The Divergence Over Time

At the moment of first supply, if `liquidityIndex = 1.0` (simplified), then `1 cToken unit ≈ 1 scaled unit` and the
error is negligible. As interest accrues and the liquidity index grows to, say, `1.05`:

- **Supply credits:** `cTokenAmount * multiplier / 1e6` ≈ `cTokenAmount / liquidityIndex` — correctly smaller than the
  nominal amount, reflecting proper scaled units
- **Withdraw debits:** `cTokenAmount` — the raw nominal amount, which is larger than the correct scaled debit

The subtracted value is consistently too large relative to what was added, meaning `scaledBalances` decreases by more
than it should per unit of actual value withdrawn. The user's tracked collateral is undercounted after a withdrawal, not
overcounted — so the `maxBorrowablePerAsset` would actually be _understated_, not overstated.

Supply adds `amount / liquidityIndex` (scaled units, which is a smaller number). Withdraw subtracts `amount` (nominal
cToken units, which is a larger number). So withdraw subtracts _more_ than supply added for the same nominal amount.
This means `scaledBalances` decreases faster than it should, understating collateral after a withdrawal. However, the
LTV-gated borrow check uses `maxBorrowablePerAsset` computed from `scaledBalances`, so undercounted collateral means
_reduced_ borrow capacity. This is a loss of user funds rather than an over-collateral exploit.

The more precise impact: if a user supplies X and withdraws X in the same transaction (liquidityIndex = 1.05):

- Supply adds `X / 1.05` to `scaledBalances`
- Withdraw subtracts `X` from `scaledBalances`
- Net change: `-X * (1 - 1/1.05)` = `-X * 0.0476` even though the user should be at zero

Over many cycles, `scaledBalances` drifts below zero in the encrypted FHE domain. Because TFHE integers are unsigned and
wrap under subtraction, `TFHE.sub` on an underflowed `euint64` produces a very large encrypted value (wraps to near
`type(uint64).max`). This flips the direction entirely: `scaledBalances` now registers as a massive number,
`maxBorrowablePerAsset` becomes astronomically large, and any subsequent borrow cap check passes unconditionally.

The downstream consequence in `_setMaxBorrowables`:

```solidity
// Called after every supply/withdraw/borrow/repay
s.userMaxBorrowablePerAsset[sender][asset] = TFHE.div(
    TFHE.mul(currentBalance, uint64(ltv)),
    uint64(10000)
);
```

With `currentBalance` wrapping to `~2^64`, the resulting `maxBorrowablePerAsset` is effectively uncapped, and the borrow
solvency check in `LibBorrowRequest`:

```solidity
euint64 maxBorrowable = s.userMaxBorrowablePerAsset[msg.sender][asset];
euint64 safeAmount = TFHE.select(
    TFHE.le(amount, maxBorrowable),
    amount,
    TFHE.asEuint64(0)
);
```

will always resolve to `amount`, regardless of actual collateral. The user can borrow any amount after triggering the
underflow.

---

## Steps to Reproduce

1. Deploy the Diamond with `SupplyFacet`, `WithdrawFacet`, `BorrowFacet`, and `AdminFacet`. Deploy `cERC20` wrapping
   USDC. Register the mapping via `AdminFacet.setCTokenAddress`. Set `REQUEST_THRESHOLD = 1` for single-user testing.

2. As **Alice**, wrap 1000 USDC → 1000 cUSDC. Call `SupplyFacet.supplyRequest(USDC, enc(1000), 0)`. Allow the Gateway
   callback and `finalizeSupplyRequests` to complete. Alice's `scaledBalances[alice][USDC]` is now approximately
   `1000 / liquidityIndex` in Aave scaled units (e.g., `952` if `liquidityIndex = 1.05`).

3. Wait for at least one block of Aave interest accrual so `liquidityIndex > 1.0` (or simulate by manipulating time on a
   fork).

4. Call `WithdrawFacet.withdrawRequest(USDC, enc(1000))`. Allow the Gateway callback and `finalizeWithdrawRequests` to
   complete. Observe that `_processStateUpdates` subtracts `1000` from `scaledBalances[alice][USDC]`, which currently
   holds `952`. The subtraction `952 - 1000` underflows the `euint64`.

5. Call `GetterFacet.getMaxBorrowable(alice, USDC)` and decrypt the result via the Gateway. Observe that the returned
   value is near `type(uint64).max * LTV / 10000` rather than `0`.

6. As Alice, call `BorrowFacet.borrowRequest(USDC, enc(largeAmount), ...)` for an amount far exceeding her actual (now
   zero) collateral. The `TFHE.select` solvency check passes because `maxBorrowable` has wrapped to a near-maximum
   value. Alice receives borrowed cTokens backed by no collateral.

---

## Recommended Fix

`_processStateUpdates` in `LibWithdrawRequest` must mirror the multiplier-based unit conversion used in
`LibSupplyRequest`. The correct approach is to measure the actual change in the Diamond's aToken scaled balance before
and after the `aavePool.withdraw` call (which already happens in `callbackWithdrawRequest`) and use that delta to
compute a withdrawal multiplier.

Move the Aave pool interaction from `callbackWithdrawRequest` into `finalizeWithdrawRequest`, where the multiplier can
be computed and passed to `_processStateUpdates`:

```solidity
function finalizeWithdrawRequest(uint256 requestId) internal {
    LibAdapterStorage.Storage storage s = LibAdapterStorage.getStorage();
    ...
    address asset    = requests[0].asset;
    address aToken   = s.aavePool.getReserveData(asset).aTokenAddress;
    address cToken   = s.tokenAddressToCTokenAddress[asset];

    uint256 amount = s.requestIdToAmount[requestId]; // decrypted total from callback
    if (amount == 0) revert LibAdapterStorage.AmountIsZero();

    // Measure before/after to get exact scaled balance delta
    uint256 beforeScaled = IScaledBalanceToken(aToken).scaledBalanceOf(address(this));
    s.aavePool.withdraw(asset, amount, address(this));
    uint256 afterScaled  = IScaledBalanceToken(aToken).scaledBalanceOf(address(this));

    uint256 difference = beforeScaled - afterScaled;       // scaled units redeemed
    uint256 multiplier = difference / (amount / (10 ** 6)); // scaled units per cToken unit

    // Wrap recovered ERC20 back to cTokens
    IERC20(asset).approve(cToken, amount);
    ConfidentialERC20Wrapped(cToken).wrap(amount);

    _processStateUpdates(s, requests, multiplier, asset, cToken);
    ...
}

function _processStateUpdates(
    LibAdapterStorage.Storage storage s,
    LibAdapterStorage.WithdrawRequestData[] memory requests,
    uint256 multiplier,   // ← added parameter
    address asset,
    address cToken
) internal {
    for (uint256 i = 0; i < requests.length; i++) {
        // Subtract in Aave scaled units, matching how supply credited them
        euint64 scaledDebit = TFHE.div(
            TFHE.mul(requests[i].amount, uint64(multiplier)),
            1e6
        );
        s.scaledBalances[requests[i].sender][asset] = TFHE.sub(
            s.scaledBalances[requests[i].sender][asset],
            scaledDebit   // ← now in Aave scaled units, symmetric with supply
        );
        ...
    }
}
```

Additionally, add an underflow guard using a saturating subtraction or a prior minimum check to ensure `scaledBalances`
never wraps below zero, regardless of rounding:

```solidity
euint64 current = s.scaledBalances[requests[i].sender][asset];
ebool isUnderflow = TFHE.lt(current, scaledDebit);
euint64 safeDebit = TFHE.select(isUnderflow, current, scaledDebit);
s.scaledBalances[requests[i].sender][asset] = TFHE.sub(current, safeDebit);
```

# MEDIUM ISSUES

---

## Issue Title [M1]

`AdminFacet.initMappings()` pushes to `aaveAssets[]` without deduplication and provides no removal function — repeated
calls permanently bloat the array, corrupt `maxBorrowablePerAsset` computations, and brick all post-operation state
updates via unbounded gas consumption

---

## Summary

`AdminFacet.initMappings()` appends asset addresses to the `s.aaveAssets[]` storage array every time it is called, with
no check for duplicate entries and no corresponding removal function. `aaveAssets[]` is iterated in full by
`_setMaxBorrowables()`, which is called at the end of every supply, withdraw, borrow, and repay finalization for every
user in the batch. Duplicate entries cause `userMaxBorrowablePerAsset[user][asset]` to be written multiple times per
user per operation, with the last write silently overwriting prior ones. As the array grows unboundedly — whether by
operator misconfiguration, repeated initialization calls, or deliberate abuse given the missing `onlyOwner` guard
identified in finding `AdminFacet` critical configuration functions are unprotected `onlyOwner` modifier is defined but
never applied, allowing any caller to reconfigure the protocol the gas cost of every state update grows linearly until
all four operation paths become permanently non-executable due to block gas limit exhaustion. There is no admin function
to shrink or correct the array.

---

## Vulnerability Details

### The Unguarded Push

`initMappings()` unconditionally appends every token in the input array to `s.aaveAssets[]`:

```solidity
// AdminFacet.initMappings()
function initMappings(address user, address[] memory tokens) external {
    LibAdapterStorage.Storage storage s = LibAdapterStorage.getStorage();

    for (uint256 i = 0; i < tokens.length; i++) {
        if (!TFHE.isInitialized(s.scaledBalances[user][tokens[i]])) {
            s.scaledBalances[user][tokens[i]] = TFHE.asEuint64(0);
            ...
        }
        if (!TFHE.isInitialized(s.scaledDebts[user][tokens[i]])) {
            s.scaledDebts[user][tokens[i]] = TFHE.asEuint64(0);
            ...
        }
        if (!TFHE.isInitialized(s.userMaxBorrowablePerAsset[user][tokens[i]])) {
            s.userMaxBorrowablePerAsset[user][tokens[i]] = TFHE.asEuint64(0);
            ...
        }

        s.aaveAssets.push(tokens[i]); // ← no deduplication guard
    }
}
```

The FHE state initializations are correctly guarded by `TFHE.isInitialized` — they only write if uninitialized, so
repeated calls for the same user are idempotent for the mapping writes. But `s.aaveAssets.push` has no equivalent guard.
Every call for any user with any token list appends unconditionally. Calling `initMappings(alice, [USDC])` three times
results in `aaveAssets = [USDC, USDC, USDC]`.

### Where `aaveAssets[]` Is Consumed

`_setMaxBorrowables()` is a shared internal function implemented identically across all four operation libraries —
`LibSupplyRequest`, `LibWithdrawRequest`, `LibBorrowRequest`, and `LibRepayRequest`. It is called once per user per
finalized batch:

```solidity
function _setMaxBorrowables(euint64 currentBalance, address sender) internal {
  LibAdapterStorage.Storage storage s = LibAdapterStorage.getStorage();

  address[] memory aaveAssets = s.aaveAssets; // loads entire array into memory

  for (uint256 i = 0; i < aaveAssets.length; i++) {
    address asset = aaveAssets[i];

    (, uint256 ltv, , , , , , , , ) = s.aaveDataProvider.getReserveConfigurationData(asset); // external call per entry

    s.userMaxBorrowablePerAsset[sender][asset] = TFHE.div(TFHE.mul(currentBalance, uint64(ltv)), uint64(10000)); // FHE operation per entry

    TFHE.allow(s.userMaxBorrowablePerAsset[sender][asset], sender);
    TFHE.allowThis(s.userMaxBorrowablePerAsset[sender][asset]);
  }
}
```

Each iteration performs:

- One external `STATICCALL` to `aaveDataProvider.getReserveConfigurationData` (~2,100 gas cold, ~100 gas warm)
- One FHE multiplication (`TFHE.mul`) substantially more expensive than standard EVM arithmetic
- One FHE division (`TFHE.div`)
- Two FHE ACL permission writes (`TFHE.allow`, `TFHE.allowThis`)

With a legitimate deployment of two assets, this loop runs twice per user per finalized batch — expected and affordable.
With `aaveAssets` inflated to 50 entries via repeated `initMappings` calls, it runs 50 times. With 500 entries it almost
certainly exceeds the block gas limit for a `REQUEST_THRESHOLD`-sized batch, making `finalizeSupplyRequests`,
`finalizeBorrowRequests`, `finalizeWithdrawRequest`, and `finalizeRepayRequests` all permanently unreachable.

### Duplicate Writes Corrupt `maxBorrowablePerAsset`

Beyond gas, duplicate entries in `aaveAssets` cause repeated writes to `userMaxBorrowablePerAsset[sender][asset]` within
a single `_setMaxBorrowables` call. With `aaveAssets = [USDC, USDC, USDC]`, the loop writes three separate FHE
ciphertexts to the same slot in sequence. Because each FHE operation produces a fresh ciphertext handle, the first two
writes are orphaned — their handles are written to storage and immediately overwritten by the next iteration. These
orphaned ciphertext handles are never cleaned up from the FHE coprocessor's ACL, accumulating stale permission entries.
The final write is the one that persists, which happens to be semantically identical to the first — so the value is
correct in isolation but the wasted work and orphaned handles grow with every duplicate.

### The Missing Removal Function

`LibAdapterStorage.Storage` defines `aaveAssets` as a plain dynamic array with no associated set membership tracker:

```solidity
struct Storage {
    ...
    address[] aaveAssets;
    mapping(address => address) tokenAddressToCTokenAddress;
    mapping(address => address) cTokenAddressToTokenAddress;
    ...
}
```

There is no `removeAsset`, `deregisterToken`, or `clearAssets` function anywhere in the codebase. Once an address is in
`aaveAssets`, it cannot be removed by any caller including the owner. If a supported asset needs to be deprecated from
Aave (a normal operational event — Aave regularly adds and removes reserve support), there is no mechanism to remove it
from `aaveAssets`, meaning its LTV will continue to be fetched and its slot will continue to be written in every
`_setMaxBorrowables` call for every user forever.

---

## Steps to Reproduce

**Scenario A — Operator misconfiguration (unintentional):**

1. Deploy the Diamond with all facets. Register USDC via `setCTokenAddress`.

2. Call `initMappings(alice, [USDC])` to initialize Alice's state — correct first call.

3. Onboard a second user Bob: call `initMappings(bob, [USDC])`. `aaveAssets` is now `[USDC, USDC]` because no
   deduplication check exists.

4. Onboard a third user Carol: `initMappings(carol, [USDC])`. `aaveAssets = [USDC, USDC, USDC]`.

5. After `N` users are onboarded, `aaveAssets` contains `N` copies of USDC. Call `finalizeSupplyRequests` with a batch
   of 3 users and observe gas cost scales with `N`, not with the number of supported assets.

**Scenario B — Active griefing attack (no `onlyOwner` guard):**

1. From any EOA, call `initMappings(address(0), [USDC])` in a loop across 100 transactions. Each call appends USDC once.
   `aaveAssets` grows to length 100+.

2. Trigger a supply batch by having 3 users call `supplyRequest`. Allow the Gateway callback to fire.

3. Call `finalizeSupplyRequests`. Observe the transaction reverts with out-of-gas because `_setMaxBorrowables` now
   iterates 100+ times per user, across 3 users, with FHE operations and external calls per iteration.

4. No further supply, borrow, withdraw, or repay batches can ever be finalized. The protocol is halted. All user funds
   already deposited into the Diamond are frozen.

---

## Recommended Fix

Three independent fixes should be applied together:

**Fix 1 — Add deduplication to `initMappings`:**

Track registered assets in a mapping to make the push idempotent:

```solidity
// Add to LibAdapterStorage.Storage struct:
mapping(address => bool) public isRegisteredAaveAsset;

// In initMappings:
function initMappings(address user, address[] memory tokens) external onlyOwner {
    LibAdapterStorage.Storage storage s = LibAdapterStorage.getStorage();

    for (uint256 i = 0; i < tokens.length; i++) {
        // Only push if not already registered
        if (!s.isRegisteredAaveAsset[tokens[i]]) {
            s.aaveAssets.push(tokens[i]);
            s.isRegisteredAaveAsset[tokens[i]] = true;
        }

        // FHE state initialization — unchanged
        if (!TFHE.isInitialized(s.scaledBalances[user][tokens[i]])) {
            s.scaledBalances[user][tokens[i]] = TFHE.asEuint64(0);
            TFHE.allowThis(s.scaledBalances[user][tokens[i]]);
            TFHE.allow(s.scaledBalances[user][tokens[i]], user);
        }
        // ... same for scaledDebts and userMaxBorrowablePerAsset
    }
}
```

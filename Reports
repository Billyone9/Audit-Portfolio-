# Audit Report:

---

## Issue Title

Sale Return Can Exceed Reserve Balance Due to Precision Loss in Power Function Approximation

**Intern** @Billyone9

**Severity:** High

**Protocol:** Castr protocol

**Affected Contract:** `BancorBondingCurve.sol`

**Affected Functions:** `calculateSaleReturn` , `power`

---

## Brief Description of the Vulnerability

The `calculateSaleReturn` function in BancorBondingCurve.sol can compute a sale return amount that exceeds the available reserve balance, violating a fundamental invariant of the bonding curve. This occurs due to precision loss in the `power` function when handling large exponents and bases during near-full-supply sales.

## Issue Description

### Summary

The Bancor bonding curve implementation allows users to sell tokens for ETH based on a mathematical formula. However, due to approximation errors in the fixed-point exponentiation used for sale calculations, the function can return more ETH than exists in the reserve, potentially leading to over-withdrawal or contract insolvency. This affects the contract's economic integrity and could enable exploits in high-stakes scenarios.

### Vulnerability Details

- **Location**: BancorBondingCurve.sol, `calculateSaleReturn` function.
- **Root Cause**: The `power` function uses fixed-point arithmetic with limited precision (up to 127 bits) and precomputed `maxExpArray` bounds. For sale operations, the exponent is `MAX_RESERVE_RATIO / _reserveRatio` (e.g., ~277 for a 0.36% reserve ratio), which is large. When selling large amounts (e.g., 99.9% of supply), the base `_supply / (_supply - _sellAmount)` becomes very large, causing the exponentiation to hit precision limits. This leads to underestimation or overestimation of the result, making `1 - (1 - sellFraction)^exponent` incorrect and potentially negative or >1 in fixed-point terms.
- **Impact**:
  - Reserve can be drained beyond available balance.
  - Breaks monotonicity (larger sells may return less ETH).
  - Fails boundary tests for near-full-supply sales.

### Steps to Reproduce

1. Deploy the `BancorBondingCurve` contract with production parameters (supply: 94,955,060,000 ether, balance: 0.4977908 ether, ratio: 3606).
2. Call `calculateSaleReturn` with a large sell amount (e.g., 99.9% of supply: ~94,905,509,394 ether).
3. Observe that the returned ETH amount exceeds the reserve balance (0.4977908 ether), violating the invariant.

### Recommended Fix

Add a cap in `calculateSaleReturn` to ensure the return never exceeds the reserve balance:

```solidity
uint256 ret = (oldBalance - newBalance) / result;
return ret > _reserveBalance ? _reserveBalance : ret;
```

For a complete fix, enhance the `power` function's precision handling for large exponents, possibly by using higher-precision arithmetic or alternative libraries.

# Audit Report

---

# Issue Title

Missing Request ID Validation in `handleOracleFulfillment()` Allows Stale or Replayed Oracle Responses to Be Accepted

**Intern** @Billyone9

**Severity:** High

**Protocol:**  Castr protocol

**Affected Contract:** `RewardResolver.sol`

**Affected Functions:** `handleOracleFulfillment()` , `_sendFunctionRequest()`

---

---

# Brief description of the vulnerability

The contract assigns `s_lastRequestId` when sending an oracle request but fails to validate the `requestId` during fulfillment. As a result, stale, replayed, or out-of-order oracle responses can be accepted and processed, potentially leading to incorrect state updates such as selecting an invalid winner or distributing rewards incorrectly.

---

# Issue Description

## Summary

The `RewardResolver` contract stores the latest oracle request identifier in `s_lastRequestId` when `_sendFunctionRequest()` is called. However, the `handleOracleFulfillment()` function does not verify that the incoming `requestId` matches `s_lastRequestId`.

Without this validation, the contract cannot ensure that the response corresponds to the most recent request. This allows stale, replayed, or out-of-order oracle responses to be processed and update critical state variables.

The presence of the unused custom error `RewardResolver__UnexpectedRequestID` indicates that request validation was intended but not implemented, resulting in a broken request–response integrity guarantee.

---

## Vulnerability Details

The contract follows the Chainlink asynchronous request pattern:

```solidity
function _sendFunctionRequest() internal {
    bytes32 requestId = sendRequest(...);
    s_lastRequestId = requestId;

    emit RequestSent(requestId);
}
```

However, during fulfillment:

```solidity
function handleOracleFulfillment(
    bytes32 requestId,
    bytes memory response,
    bytes memory err
) internal override {
    _processWinner(response);
}
```

There is **no validation** that:

```solidity
requestId == s_lastRequestId
```

This breaks the expected invariant:

```
Only the latest request response should be processed
```

Asynchronous oracle systems may return responses:

- out of order
- duplicated
- delayed
- replayed

Without request ID validation, any valid fulfillment from the oracle infrastructure can overwrite protocol state, even if it corresponds to an outdated request.

For example:

```
Request A sent
Request B sent
Response B arrives
Response A arrives later
```

The contract will:

```
Process Response B
Then overwrite state with Response A
```

This leads to:

- incorrect winner selection
- incorrect randomness usage
- stale price or computation data
- inconsistent protocol state
- potential financial loss

The defined but unused custom error:

```solidity
error RewardResolver__UnexpectedRequestID(bytes32 requestId);
```

confirms that request validation logic was intended but omitted.

---

## Steps to Reproduce

1. Send an oracle request and store the returned `requestId` as `s_lastRequestId`
2. Send another oracle request before the first response is fulfilled
3. Allow the second request response to be processed normally
4. Later, fulfill the first (older) request response
5. Observe that the contract accepts the stale response and updates the state incorrectly

---

## Recommended Fix

Add request ID validation inside `handleOracleFulfillment()` to ensure only the latest request response is processed.

```solidity
function handleOracleFulfillment(
    bytes32 requestId,
    bytes memory response,
    bytes memory err
) internal override {
    if (requestId != s_lastRequestId) {
        revert RewardResolver__UnexpectedRequestID(requestId);
    }

    _processWinner(response);
}
```




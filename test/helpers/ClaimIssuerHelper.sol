// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Vm } from "forge-std/Vm.sol";

import { ClaimIssuer } from "contracts/ClaimIssuer.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";

/// @notice Helper library for deploying ClaimIssuer contracts with proxy
library ClaimIssuerHelper {

    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @notice Deploys a ClaimIssuer behind an ERC1967Proxy and installs the given validator
    ///         module so the issuer can verify ECDSA-signed claims through its `isClaimValid`.
    /// @param initialManagementKey The management key for the claim issuer
    /// @param ecdsaValidator The ECDSA validator module to install on the issuer
    /// @return claimIssuer The ClaimIssuer contract at the proxy address
    function deployWithProxy(address initialManagementKey, address ecdsaValidator) internal returns (ClaimIssuer) {
        ClaimIssuer impl = new ClaimIssuer(initialManagementKey);
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl), abi.encodeCall(ClaimIssuer.initialize, (initialManagementKey, IdentityTypes.CLAIM_ISSUER))
        );
        ClaimIssuer claimIssuer = ClaimIssuer(payable(address(proxy)));

        // Install the validator module so `isClaimValid` can dispatch through it.
        vm.prank(initialManagementKey);
        claimIssuer.installModule(MODULE_TYPE_VALIDATOR, ecdsaValidator, "");

        return claimIssuer;
    }

}

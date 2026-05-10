// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import {Identity} from "contracts/Identity.sol";
import {IdFactory} from "contracts/factory/IdFactory.sol";
import {IdentityTypes} from "contracts/libraries/IdentityTypes.sol";
import {IdentityProxy} from "contracts/proxy/IdentityProxy.sol";
import {
    ImplementationAuthority
} from "contracts/proxy/ImplementationAuthority.sol";

/// @notice Helper library for deploying OnchainID Identity Factory infrastructure
library IdentityHelper {
    struct OnchainIDSetup {
        Identity identityImplementation;
        ImplementationAuthority implementationAuthority;
        IdFactory idFactory;
    }

    function deployFactory(
        address managementKey,
        address createx,
        address owner
    ) internal returns (OnchainIDSetup memory setup) {
        setup.identityImplementation = new Identity(managementKey, false);
        setup.implementationAuthority = new ImplementationAuthority(
            address(setup.identityImplementation),
            owner
        );
        setup.idFactory = new IdFactory(
            address(setup.implementationAuthority),
            createx,
            owner
        );
    }

    /// @notice Deploys an Identity through the custom IdentityProxy pattern (defaults to INDIVIDUAL type)
    /// @param initialManagementKey The management key for the identity
    /// @return identity The Identity contract at the proxy address
    function deployIdentityWithProxy(
        address initialManagementKey
    ) internal returns (Identity) {
        return
            deployIdentityWithProxy(
                initialManagementKey,
                IdentityTypes.INDIVIDUAL
            );
    }

    function deployIdentityWithProxy(
        address initialManagementKey,
        uint256 identityType
    ) internal returns (Identity) {
        Identity impl = new Identity(initialManagementKey, false);
        ImplementationAuthority ia = new ImplementationAuthority(
            address(impl),
            initialManagementKey
        );
        IdentityProxy proxy = new IdentityProxy(
            address(ia),
            initialManagementKey,
            identityType
        );
        return Identity(address(proxy));
    }
}

// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @notice Mock implementation that matches the real registry and factory but leaves its
///         initializers open, so the factory's beacon shape check rejects it.
contract UnlockedIdentity {

    address private immutable _registryModule;
    address private immutable _identityFactory;

    constructor(address registryModule_, address identityFactory_) {
        _registryModule = registryModule_;
        _identityFactory = identityFactory_;
    }

    function registryModule() external view returns (address) {
        return _registryModule;
    }

    function identityFactory() external view returns (address) {
        return _identityFactory;
    }

    /// @dev Never initialized, so the version reads 0 rather than the locked sentinel.
    function initializedVersion() external pure returns (uint64) {
        return 0;
    }

}

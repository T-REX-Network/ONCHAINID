// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @notice Stand-in for an implementation built against a newer registry interface than the
///         deployed registry has. It passes every other beacon shape check: same factory, same
///         registry, locked initializers, release version "3.1.0".
contract IdentityNeedingNewerRegistry {

    bytes4 public constant NEWER_REGISTRY_INTERFACE = 0x12345678;

    address private immutable _identityFactory;
    address private immutable _registryModule;

    constructor(address identityFactory_, address registryModule_) {
        _identityFactory = identityFactory_;
        _registryModule = registryModule_;
    }

    function identityFactory() external view returns (address) {
        return _identityFactory;
    }

    function registryModule() external view returns (address) {
        return _registryModule;
    }

    function requiredRegistryInterface() external pure returns (bytes4) {
        return NEWER_REGISTRY_INTERFACE;
    }

    function initializedVersion() external pure returns (uint64) {
        return type(uint64).max;
    }

    function version() external pure returns (string memory) {
        return "3.1.0";
    }

}

// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

import { Identity } from "../Identity.sol";
import { Structs } from "../storage/Structs.sol";

contract IdentityProxy is BeaconProxy {

    constructor(
        address _implementationAuthority,
        uint256 _identityType,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory modules
    ) BeaconProxy(_implementationAuthority, abi.encodeCall(Identity.initialize, (_identityType, _keys, modules))) { }

}

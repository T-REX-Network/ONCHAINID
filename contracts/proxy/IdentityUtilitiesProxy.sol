// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IdentityUtilities } from "../IdentityUtilities.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract IdentityUtilitiesProxy is ERC1967Proxy {

    /// @dev Takes the admin instead of raw init data, so the proxy can only ever be
    ///      deployed initialized. An uninitialized one is open for anyone to claim.
    constructor(address implementation, address admin)
        ERC1967Proxy(implementation, abi.encodeCall(IdentityUtilities.initialize, (admin)))
    { }

}

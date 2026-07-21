// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

/// @notice Locks the ERC-7930 envelope bytes produced by OZ's `draft-InteroperableAddress`.
///
///         The factory's wallet-to-identity mapping is keyed by these bytes: a wallet is
///         linked under whatever `formatEvmV1` produced at link time, and every later
///         lookup must reproduce the exact same bytes to find it. The library lives in
///         OZ's `draft-` namespace, which carries no stability guarantee — if a future OZ
///         upgrade changes the encoding, previously linked wallets silently stop
///         resolving and identity claims read `NotIssued`.
///
///         These golden vectors hardcode the expected wire format per ERC-7930 v1
///         (`0x0001` version ++ `0x0000` eip155 chain type ++ length-prefixed minimal
///         big-endian chainid ++ `0x14` ++ 20-byte address), independently of the
///         library. An OZ bump that alters `formatEvmV1` fails here instead of freezing
///         linked wallets in production. If this test ever breaks on a dependency
///         upgrade, treat it as a storage migration: existing envelope keys in
///         `IdentityFactory` were written under the old encoding.
contract InteroperableAddressEncodingTest is OnchainIDSetup {

    address internal constant ADDR_A = 0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa;
    address internal constant ADDR_B = 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB;

    /// @notice Single-byte chainid (Ethereum mainnet, 1).
    function test_formatEvmV1_goldenVector_singleByteChainId() public pure {
        bytes memory expected = hex"00010000010114aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assertEq(InteroperableAddress.formatEvmV1(1, ADDR_A), expected);
    }

    /// @notice Multi-byte chainid (Base, 8453 = 0x2105).
    function test_formatEvmV1_goldenVector_multiByteChainId() public pure {
        bytes memory expected = hex"0001000002210514bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assertEq(InteroperableAddress.formatEvmV1(8453, ADDR_B), expected);
    }

    /// @notice Round trip through the factory: an envelope hand-built from the golden
    ///         wire format resolves a wallet the factory linked under bytes it computed
    ///         itself with `formatEvmV1`. Alice was auto-linked at identity creation, so
    ///         a mismatch between stored key and hand-built key breaks this lookup.
    function test_factoryLookup_matchesHandBuiltEnvelope() public view {
        // Foundry's default chainid, 31337 = 0x7a69.
        bytes memory handBuilt = abi.encodePacked(hex"0001000002" hex"7a69" hex"14", alice);

        assertEq(InteroperableAddress.formatEvmV1(block.chainid, alice), handBuilt);
        assertEq(onchainidSetup.idFactory.getIdentity(handBuilt), address(aliceIdentity));
    }

}

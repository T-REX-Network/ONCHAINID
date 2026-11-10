// SPDX-License-Identifier: CC0-1.0
//
// Copied from the ERC-8100 reference assets (ethereum/ERCs, assets/erc-8100/contracts/IRepresentableState.sol).

pragma solidity ^0.8.27;

/// @title IXMLRepresentableState
/// @notice ERC-8100: a contract that exposes a static XML template whose `evmstate:*` bindings an
///         off-chain renderer resolves against this same contract at one block.
interface IXMLRepresentableState {

    /// @notice The static XML template with `evmstate` bindings (namespace `urn:evm:state:1.0`).
    function stateXmlTemplate() external view returns (string memory);

}

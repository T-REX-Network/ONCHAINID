// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";

/// @dev An EIP-7702 delegate that puts code on an EOA without implementing ERC-1271.
contract NoERC1271Delegate {

    uint256 public counter;

    function bump() external {
        counter++;
    }

}

/// @dev A delegate that implements `isValidSignature` but expects a wrapped signature format,
///      so it rejects the raw 65-byte ECDSA blob stored on the claim.
contract PickyERC1271Delegate {

    function isValidSignature(bytes32, bytes calldata signature) external pure returns (bytes4) {
        if (signature.length == 65) return 0xffffffff;
        return 0x1626ba7e;
    }

}

/// @notice The key path (`_verify`) and the claim path (`_getClaimStatus`) must agree on what a
///         valid signature is. Before the fix the claim path went through
///         `SignatureChecker.isValidSignatureNow`, which skips ECDSA recovery entirely once the
///         signer address carries code — so an EIP-7702 delegation on a claim-signer EOA could
///         flip an unrevoked, unexpired claim to `BadSignature` without the issuer or the holder
///         touching anything.
contract ClaimSignatureDefinitionTest is OnchainIDSetup {

    /// @dev The module reads the issuer from `msg.sender`, so call the singleton pranked as the
    ///      issuer identity rather than through its fallback (no claims handler on the issuer).
    function _statusOf(bytes memory sig) internal returns (IClaimIssuer.ClaimStatus) {
        ERC734Validator module = onchainidSetup.signatureValidator;
        vm.prank(address(claimIssuer));
        return module.getClaimStatus(IIdentity(address(aliceIdentity)), aliceClaim666.topic, sig, aliceClaim666.data);
    }

    function _status() internal returns (IClaimIssuer.ClaimStatus) {
        return _statusOf(aliceClaim666.signature);
    }

    function test_claimStaysValidWhenSignerIsCodelessEOA() public {
        assertEq(uint256(_status()), uint256(IClaimIssuer.ClaimStatus.Valid));
    }

    function test_claimStaysValidAfterSignerGainsCodeWithoutERC1271() public {
        assertEq(uint256(_status()), uint256(IClaimIssuer.ClaimStatus.Valid), "precondition");

        vm.etch(claimIssuerOwner, address(new NoERC1271Delegate()).code);
        assertGt(claimIssuerOwner.code.length, 0, "signer must carry code");

        assertEq(
            uint256(_status()),
            uint256(IClaimIssuer.ClaimStatus.Valid),
            "ECDSA signature must still verify once the signer is delegated"
        );
    }

    function test_claimStaysValidWhenDelegateRejectsRawSignature() public {
        vm.etch(claimIssuerOwner, address(new PickyERC1271Delegate()).code);

        assertEq(
            uint256(_status()),
            uint256(IClaimIssuer.ClaimStatus.Valid),
            "a delegate that rejects the raw blob must not invalidate the claim"
        );
    }

    /// @dev The 1271 fallback stays reachable: a signer whose blob is not a valid ECDSA signature
    ///      for it is still accepted when its code says the signature is good.
    function test_erc1271FallbackStillAccepts() public {
        vm.etch(claimIssuerOwner, address(new PickyERC1271Delegate()).code);

        // A 64-byte blob can never ECDSA-recover to the signer, so this can only pass via 1271.
        bytes memory signer = abi.encodePacked(claimIssuerOwner);
        bytes memory rawSig = new bytes(64);
        assertEq(
            uint256(_statusOf(abi.encode(signer, rawSig))),
            uint256(IClaimIssuer.ClaimStatus.Valid),
            "1271 branch must remain reachable"
        );
    }

}

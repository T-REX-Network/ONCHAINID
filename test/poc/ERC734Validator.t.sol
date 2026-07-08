// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { IAccount, PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import { MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";

/// @notice Coverage for `ERC734Validator`. Checks the registry, per-target scoping, and the
///         claim-visibility limitation:
///           - multi-purpose signer (ACTION + CLAIM_SIGNER)
///           - claim-signer-only scoping
///           - management self-targets anything
///           - full signerData/clientData round-trip per account
///           - account delegates the decision to the validator
///           - a module-held CLAIM_SIGNER is not visible to ERC-735 claim verification
contract ERC734ValidatorTest is OnchainIDSetup {

    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    ERC734Validator internal validator;

    // Signer registered INSIDE the module as the account's manager at install.
    address internal mgr;
    uint256 internal mgrPk;

    function setUp() public virtual override {
        super.setUp();
        (mgr, mgrPk) = makeAddrAndKey("erc734-mgr");
        validator = new ERC734Validator();

        // Install on alice with `mgr` as the module's MANAGEMENT key. The account no longer
        // scopes userOps, so no account-layer purpose grant to the validator is needed; the
        // module is the sole authority on what its signers may do.
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encodePacked(mgr));
    }

    // --- helpers ---------------------------------------------------------

    function _packNonce(address v, uint96 seq) internal pure returns (uint256) {
        return (uint256(uint160(v)) << 96) | uint256(seq);
    }

    function _buildUserOp(address target, bytes memory innerCall)
        internal
        view
        returns (PackedUserOperation memory userOp, bytes32 userOpHash)
    {
        bytes memory executionCalldata = abi.encodePacked(target, uint256(0), innerCall);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), bytes32(0), executionCalldata);
        userOp = PackedUserOperation({
            sender: address(aliceIdentity),
            nonce: _packNonce(address(validator), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
        userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));
    }

    function _sign(uint256 pk, address who, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encode(abi.encodePacked(who), abi.encodePacked(r, s, v));
    }

    /// @dev Register `who` as an ECDSA key with `purpose` in the module, via a self-call from
    ///      the account (`msg.sender == aliceIdentity`). `signerData = abi.encodePacked(who)`,
    ///      empty `clientData`. Uses vm.prank on the account address.
    function _moduleAddKey(address who, uint256 purpose) internal {
        vm.prank(address(aliceIdentity));
        validator.addKey(
            abi.encodePacked(who),
            "",
            purpose,
            1 /* ECDSA */
        );
    }

    // --- tests -----------------------------------------------------------

    /// @notice One signer holding ACTION + CLAIM_SIGNER: external transfer and self-addClaim
    ///         pass, self-addKey fails.
    function test_multiPurposeSigner() public {
        (address multi, uint256 multiPk) = makeAddrAndKey("multi");
        _moduleAddKey(multi, KeyPurposes.ACTION);
        _moduleAddKey(multi, KeyPurposes.CLAIM_SIGNER);

        PocCounter counter = new PocCounter();

        // external target -> ACTION -> ok
        {
            (PackedUserOperation memory userOp, bytes32 userOpHash) =
                _buildUserOp(address(counter), abi.encodeCall(PocCounter.increment, ()));
            userOp.signature = _sign(multiPk, multi, userOpHash);
            vm.prank(ENTRY_POINT);
            assertEq(
                IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0),
                ERC4337Utils.SIG_VALIDATION_SUCCESS,
                "ACTION external must pass"
            );
        }

        // self + addClaim -> CLAIM_SIGNER -> ok
        {
            bytes memory addClaim = abi.encodeWithSignature(
                "addClaim(uint256,uint256,address,bytes,bytes,string)",
                uint256(1),
                uint256(1),
                address(claimIssuer),
                bytes("sig"),
                bytes("data"),
                "uri"
            );
            (PackedUserOperation memory userOp, bytes32 userOpHash) = _buildUserOp(address(aliceIdentity), addClaim);
            userOp.signature = _sign(multiPk, multi, userOpHash);
            vm.prank(ENTRY_POINT);
            assertEq(
                IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0),
                ERC4337Utils.SIG_VALIDATION_SUCCESS,
                "CLAIM_SIGNER self-addClaim must pass"
            );
        }

        // self + addKey -> needs MANAGEMENT -> fail
        {
            bytes memory addKey = abi.encodeWithSignature(
                "addKey(bytes32,uint256,uint256)", keccak256("evil"), KeyPurposes.MANAGEMENT, uint256(1)
            );
            (PackedUserOperation memory userOp, bytes32 userOpHash) = _buildUserOp(address(aliceIdentity), addKey);
            userOp.signature = _sign(multiPk, multi, userOpHash);
            vm.prank(ENTRY_POINT);
            assertEq(
                IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0),
                ERC4337Utils.SIG_VALIDATION_FAILED,
                "non-MANAGEMENT self-addKey must fail"
            );
        }
    }

    /// @notice Claim-signer only: self-addClaim passes, external transfer fails.
    function test_claimSignerOnlyScoping() public {
        (address cs, uint256 csPk) = makeAddrAndKey("claimsigner");
        _moduleAddKey(cs, KeyPurposes.CLAIM_SIGNER);

        // external transfer -> no ACTION -> fail
        PocCounter counter = new PocCounter();
        (PackedUserOperation memory userOp1, bytes32 userOpHash1) =
            _buildUserOp(address(counter), abi.encodeCall(PocCounter.increment, ()));
        userOp1.signature = _sign(csPk, cs, userOpHash1);
        vm.prank(ENTRY_POINT);
        assertEq(
            IAccount(address(aliceIdentity)).validateUserOp(userOp1, userOpHash1, 0),
            ERC4337Utils.SIG_VALIDATION_FAILED,
            "claim-signer must not act externally"
        );

        // self addClaim -> ok
        bytes memory addClaim = abi.encodeWithSignature(
            "addClaim(uint256,uint256,address,bytes,bytes,string)",
            uint256(1),
            uint256(1),
            address(claimIssuer),
            bytes("s"),
            bytes("d"),
            "u"
        );
        (PackedUserOperation memory userOp2, bytes32 userOpHash2) = _buildUserOp(address(aliceIdentity), addClaim);
        userOp2.signature = _sign(csPk, cs, userOpHash2);
        vm.prank(ENTRY_POINT);
        assertEq(
            IAccount(address(aliceIdentity)).validateUserOp(userOp2, userOpHash2, 0),
            ERC4337Utils.SIG_VALIDATION_SUCCESS,
            "claim-signer self-addClaim must pass"
        );
    }

    /// @notice The MANAGEMENT signer from install can self-target addKey.
    function test_managementSelfTargets() public {
        bytes memory addKey =
            abi.encodeWithSignature("addKey(bytes32,uint256,uint256)", keccak256("ok"), KeyPurposes.ACTION, uint256(1));
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _buildUserOp(address(aliceIdentity), addKey);
        userOp.signature = _sign(mgrPk, mgr, userOpHash);
        vm.prank(ENTRY_POINT);
        assertEq(
            IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0),
            ERC4337Utils.SIG_VALIDATION_SUCCESS,
            "MANAGEMENT must self-target addKey"
        );
    }

    /// @notice An unregistered signer with a valid signature still fails at the module's
    ///         membership check.
    function test_accountDelegatesToValidator_unregisteredFails() public {
        (address stranger, uint256 strangerPk) = makeAddrAndKey("stranger734");
        PocCounter counter = new PocCounter();
        (PackedUserOperation memory userOp, bytes32 userOpHash) =
            _buildUserOp(address(counter), abi.encodeCall(PocCounter.increment, ()));
        userOp.signature = _sign(strangerPk, stranger, userOpHash);
        vm.prank(ENTRY_POINT);
        assertEq(
            IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0),
            ERC4337Utils.SIG_VALIDATION_FAILED,
            "unregistered signer must fail at module membership"
        );
    }

    /// @notice signerData and clientData round-trip through getKeyData/getKey and stay scoped
    ///         to the account. Uses a WebAuthn-shaped key (verifier+pubkey, credentialId).
    function test_signerAndClientDataPreservedPerAccount() public {
        // WebAuthn-shaped signerData: verifier(20) || pubkey(...). clientData: credentialId.
        bytes memory verifier = abi.encodePacked(makeAddr("p256verifier"));
        bytes memory pubkey = abi.encodePacked(keccak256("qx"), keccak256("qy"));
        bytes memory signerData = bytes.concat(verifier, pubkey);
        bytes memory clientData = abi.encodePacked(keccak256("credentialId"));
        bytes32 keyHash = keccak256(signerData);

        vm.prank(address(aliceIdentity));
        validator.addKey(
            signerData,
            clientData,
            KeyPurposes.ACTION,
            3 /* WEBAUTHN */
        );

        // Round-trips, scoped to alice.
        (bytes memory gotSigner, bytes memory gotClient) = validator.getKeyData(address(aliceIdentity), keyHash);
        assertEq(gotSigner, signerData, "signerData must be preserved");
        assertEq(gotClient, clientData, "clientData must be preserved (not collapsed)");

        (uint256[] memory purposes, uint256 keyType, bytes32 key) = validator.getKey(address(aliceIdentity), keyHash);
        assertEq(keyType, 3, "keyType must be WEBAUTHN");
        assertEq(key, keyHash, "getKey must echo the committed keyHash");
        assertEq(purposes.length, 1, "one purpose");

        // Per-account isolation: bob's registry does not see alice's key.
        (bytes memory bobSigner,) = validator.getKeyData(address(bobIdentity), keyHash);
        assertEq(bobSigner.length, 0, "another account must not see this key's data");
    }

    /// @notice A CLAIM_SIGNER registered only in the module is invisible to ERC-735 claim
    ///         verification, which reads `keyHasPurpose` on the identity account (see
    ///         `ClaimsModule._getClaimStatus`). The module knows the key but the account does
    ///         not, so a claim from this signer would resolve to NotIssued. The account has to
    ///         keep answering keyHasPurpose for claims to work.
    function test_moduleHeldClaimSignerIsInvisibleToERC735() public {
        (address csOnlyInModule,) = makeAddrAndKey("cs-module-only");
        bytes32 keyHash = keccak256(abi.encodePacked(csOnlyInModule));

        _moduleAddKey(csOnlyInModule, KeyPurposes.CLAIM_SIGNER);

        // The module knows the key.
        assertTrue(
            validator.keyHasPurpose(address(aliceIdentity), keyHash, KeyPurposes.CLAIM_SIGNER),
            "module registry must know the claim signer"
        );

        // The identity's own registry does not. This is what claim verification reads.
        assertFalse(
            aliceIdentity.keyHasPurpose(keyHash, KeyPurposes.CLAIM_SIGNER),
            "identity account must not see a module-only claim signer"
        );

        // Control: carol is a CLAIM_SIGNER on the account (from OnchainIDSetup) and is visible.
        assertTrue(
            aliceIdentity.keyHasPurpose(keccak256(abi.encodePacked(carol)), KeyPurposes.CLAIM_SIGNER),
            "account-registered claim signer must be visible"
        );
    }

}

/// @notice PoC-local counter target.
contract PocCounter {

    uint256 public count;

    function increment() external {
        count++;
    }

}

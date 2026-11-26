// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import { Base64 } from "@openzeppelin/contracts/utils/Base64.sol";
import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import { WebAuthn } from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";
import { Identity } from "contracts/Identity.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @dev The parts of the ERC-4337 v0.9 EntryPoint this test calls.
interface IEntryPointLike {

    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);

    error FailedOp(uint256 opIndex, string reason);

}

/// @dev The parts of Safe v1.4.1 this test calls.
interface ISafeLike {

    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
    function approveHash(bytes32 hashToApprove) external;
    function approvedHashes(address owner, bytes32 hash) external view returns (uint256);
    function nonce() external view returns (uint256);
    function getThreshold() external view returns (uint256);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce_
    ) external view returns (bytes32);
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) external payable returns (bool);

}

interface ISafeProxyFactoryLike {

    function createProxyWithNonce(address singleton, bytes calldata initializer, uint256 saltNonce)
        external
        returns (address proxy);

}

/// @notice A member approves a Safe transaction through an identity controlled by a passkey.
///
///         This is the approval path of the protocol's own governance: each member is an ONCHAINID
///         identity, the identity is an owner of a Safe, and the member approves a Safe transaction
///         hash by sending one ERC-4337 user operation signed with a passkey (WebAuthn, P-256).
///
///         Nothing is mocked on that path. The EntryPoint v0.9 runtime and the Safe v1.4.1 contracts
///         are the deployed bytecode (see `test/vendored`), the WebAuthn assertion is built and signed
///         the way an authenticator does it, and the user operation goes through `handleOps`.
contract PasskeySafeApprovalTest is OnchainIDSetup {

    /// @dev The canonical ERC-4337 v0.9 EntryPoint. `Account.entryPoint()` returns this address.
    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    uint256 internal constant ALICE_PASSKEY = uint256(keccak256("alice passkey"));
    uint256 internal constant BOB_PASSKEY = uint256(keccak256("bob passkey"));

    IEntryPointLike internal entryPoint = IEntryPointLike(ENTRY_POINT);
    ERC7913WebAuthnVerifier internal webAuthnVerifier;
    ISafeLike internal safe;
    Target internal target;
    address payable internal bundler;

    function setUp() public override {
        super.setUp();

        vm.etch(ENTRY_POINT, vm.readFileBinary("test/vendored/entrypoint-0.9/EntryPoint.bytecode"));
        webAuthnVerifier = new ERC7913WebAuthnVerifier();
        target = new Target();
        bundler = payable(makeAddr("bundler"));

        // Each member registers a passkey on their identity as an ACTION key.
        _addPasskey(aliceIdentity, alice, ALICE_PASSKEY);
        _addPasskey(bobIdentity, bob, BOB_PASSKEY);

        // The identities pay for their own user operations here. In production a paymaster does.
        vm.deal(address(aliceIdentity), 1 ether);
        vm.deal(address(bobIdentity), 1 ether);

        // A Safe v1.4.1 owned by the two identities. Both must approve.
        address singleton = _deploy("test/vendored/safe-1.4.1/Safe.bytecode");
        ISafeProxyFactoryLike factory =
            ISafeProxyFactoryLike(_deploy("test/vendored/safe-1.4.1/SafeProxyFactory.bytecode"));
        address[] memory owners = new address[](2);
        owners[0] = address(aliceIdentity);
        owners[1] = address(bobIdentity);
        bytes memory initializer = abi.encodeCall(
            ISafeLike.setup, (owners, 2, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        safe = ISafeLike(factory.createProxyWithNonce(singleton, initializer, 0));
        assertEq(safe.getThreshold(), 2);
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// @notice One member approves: the passkey signs a user operation, the EntryPoint runs it, and
    ///         the Safe records the identity's approval of exactly that hash.
    function test_passkeyIdentity_approvesSafeHash_throughEntryPoint() public {
        bytes32 safeTxHash = _safeTxHash();
        assertEq(safe.approvedHashes(address(aliceIdentity), safeTxHash), 0);

        _handleOp(_approveOp(aliceIdentity, ALICE_PASSKEY, safeTxHash));

        assertEq(safe.approvedHashes(address(aliceIdentity), safeTxHash), 1, "the Safe must record the approval");
        assertEq(safe.approvedHashes(address(bobIdentity), safeTxHash), 0, "nobody else approved");
    }

    /// @notice The whole decision: both members approve with their passkeys, then anybody executes
    ///         the Safe transaction. No member key ever signs the Safe transaction itself.
    function test_twoPasskeyIdentities_approve_thenAnyoneExecutes() public {
        bytes32 safeTxHash = _safeTxHash();

        _handleOp(_approveOp(aliceIdentity, ALICE_PASSKEY, safeTxHash));

        // One approval is not enough for a 2-of-2 Safe.
        vm.expectRevert(bytes("GS025"));
        _execSafeTx();

        _handleOp(_approveOp(bobIdentity, BOB_PASSKEY, safeTxHash));

        vm.prank(makeAddr("anyone"));
        _execSafeTx();
        assertEq(target.count(), 1, "the approved transaction must run once");
        assertEq(safe.nonce(), 1);
    }

    /// @notice A signature that was changed after signing is refused at validation, and the Safe
    ///         records nothing.
    function test_alteredPasskeySignature_isRefused() public {
        bytes32 safeTxHash = _safeTxHash();
        PackedUserOperation memory op = _unsignedApproveOp(aliceIdentity, safeTxHash);
        WebAuthn.WebAuthnAuth memory auth = _assertion(ALICE_PASSKEY, entryPoint.getUserOpHash(op));
        auth.r = bytes32(uint256(auth.r) ^ 1);
        op.signature = abi.encode(_signer(ALICE_PASSKEY), _encodeAuth(auth));

        _expectSignatureError();
        _handleOp(op);
        assertEq(safe.approvedHashes(address(aliceIdentity), safeTxHash), 0);
    }

    /// @notice A valid assertion over another challenge (here, another user operation) is refused:
    ///         the passkey approves one operation, not any operation.
    function test_assertionForAnotherOperation_isRefused() public {
        bytes32 safeTxHash = _safeTxHash();
        PackedUserOperation memory op = _unsignedApproveOp(aliceIdentity, safeTxHash);
        WebAuthn.WebAuthnAuth memory auth = _assertion(ALICE_PASSKEY, keccak256("another operation"));
        op.signature = abi.encode(_signer(ALICE_PASSKEY), _encodeAuth(auth));

        _expectSignatureError();
        _handleOp(op);
        assertEq(safe.approvedHashes(address(aliceIdentity), safeTxHash), 0);
    }

    /// @notice A passkey that is not registered on the identity cannot approve for it, even with a
    ///         correct assertion.
    function test_unregisteredPasskey_isRefused() public {
        bytes32 safeTxHash = _safeTxHash();
        PackedUserOperation memory op = _approveOp(aliceIdentity, BOB_PASSKEY, safeTxHash);

        _expectSignatureError();
        _handleOp(op);
        assertEq(safe.approvedHashes(address(aliceIdentity), safeTxHash), 0);
    }

    /// @notice An assertion without user verification (no biometric or PIN) is refused.
    function test_assertionWithoutUserVerification_isRefused() public {
        bytes32 safeTxHash = _safeTxHash();
        PackedUserOperation memory op = _unsignedApproveOp(aliceIdentity, safeTxHash);
        WebAuthn.WebAuthnAuth memory auth =
            _assertion(ALICE_PASSKEY, entryPoint.getUserOpHash(op), WebAuthn.AUTH_DATA_FLAGS_UP);
        op.signature = abi.encode(_signer(ALICE_PASSKEY), _encodeAuth(auth));

        _expectSignatureError();
        _handleOp(op);
        assertEq(safe.approvedHashes(address(aliceIdentity), safeTxHash), 0);
    }

    // -----------------------------------------------------------------------
    // Safe helpers
    // -----------------------------------------------------------------------

    /// @dev The Safe transaction the members decide on: one call to `target.increment()`.
    function _safeTxHash() internal view returns (bytes32) {
        return safe.getTransactionHash(
            address(target), 0, abi.encodeCall(Target.increment, ()), 0, 0, 0, 0, address(0), address(0), safe.nonce()
        );
    }

    /// @dev Executes the Safe transaction with pre-approved-hash signatures (v = 1) for both owners,
    ///      in ascending owner order as the Safe requires.
    function _execSafeTx() internal {
        (address lo, address hi) = address(aliceIdentity) < address(bobIdentity)
            ? (address(aliceIdentity), address(bobIdentity))
            : (address(bobIdentity), address(aliceIdentity));
        bytes memory signatures = abi.encodePacked(
            bytes32(uint256(uint160(lo))), bytes32(0), uint8(1), bytes32(uint256(uint160(hi))), bytes32(0), uint8(1)
        );
        safe.execTransaction(
            address(target),
            0,
            abi.encodeCall(Target.increment, ()),
            0,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            signatures
        );
    }

    function _deploy(string memory path) internal returns (address deployed) {
        bytes memory initCode = vm.readFileBinary(path);
        assembly ("memory-safe") {
            deployed := create(0, add(initCode, 0x20), mload(initCode))
        }
        require(deployed != address(0), "vendored deployment failed");
    }

    // -----------------------------------------------------------------------
    // User operation helpers
    // -----------------------------------------------------------------------

    function _handleOp(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        // The EntryPoint only accepts a call from an externally owned account.
        vm.prank(bundler, bundler);
        entryPoint.handleOps(ops, bundler);
    }

    function _expectSignatureError() internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPointLike.FailedOp.selector, 0, "AA24 signature error"));
    }

    /// @dev A user operation in which `identity` calls `safe.approveHash(safeTxHash)`, signed by `passkey`.
    function _approveOp(Identity identity, uint256 passkey, bytes32 safeTxHash)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _unsignedApproveOp(identity, safeTxHash);
        WebAuthn.WebAuthnAuth memory auth = _assertion(passkey, entryPoint.getUserOpHash(op));
        // The validator reads `abi.encode(signer, signature)`: the ERC-7913 signer, then its signature.
        op.signature = abi.encode(_signer(passkey), _encodeAuth(auth));
    }

    function _unsignedApproveOp(Identity identity, bytes32 safeTxHash)
        internal
        view
        returns (PackedUserOperation memory)
    {
        // Single-call execute payload: target (20) || value (32) || data.
        bytes memory execution =
            abi.encodePacked(address(safe), uint256(0), abi.encodeCall(ISafeLike.approveHash, (safeTxHash)));
        return PackedUserOperation({
            sender: address(identity),
            // The validator's address sits in the top 20 bytes of the nonce; the sequence is 0.
            nonce: uint256(uint160(address(onchainidSetup.signatureValidator))) << 96,
            initCode: "",
            callData: abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), bytes32(0), execution),
            // verificationGasLimit || callGasLimit. P-256 runs in Solidity here, so it is generous.
            accountGasLimits: bytes32((uint256(3_000_000) << 128) | 500_000),
            preVerificationGas: 100_000,
            // maxPriorityFeePerGas || maxFeePerGas
            gasFees: bytes32((uint256(1 gwei) << 128) | 1 gwei),
            paymasterAndData: "",
            signature: ""
        });
    }

    // -----------------------------------------------------------------------
    // Passkey helpers
    // -----------------------------------------------------------------------

    /// @dev The ERC-7913 signer of a passkey: verifier (20) || qx (32) || qy (32).
    function _signer(uint256 passkey) internal view returns (bytes memory) {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(passkey);
        return abi.encodePacked(address(webAuthnVerifier), qx, qy);
    }

    function _addPasskey(Identity identity, address manager, uint256 passkey) internal {
        bytes memory signer = _signer(passkey);
        vm.prank(manager);
        identity.addKeyWithData(keccak256(signer), KeyPurposes.ACTION, KeyTypes.WEBAUTHN, signer, "");
    }

    /// @dev The verifier reads the assertion as its six fields ABI-encoded side by side, with no
    ///      outer offset. `abi.encode(auth)` would add one and the assertion would not decode.
    function _encodeAuth(WebAuthn.WebAuthnAuth memory auth) internal pure returns (bytes memory) {
        return
            abi.encode(auth.r, auth.s, auth.challengeIndex, auth.typeIndex, auth.authenticatorData, auth.clientDataJSON);
    }

    function _assertion(uint256 passkey, bytes32 challenge) internal pure returns (WebAuthn.WebAuthnAuth memory) {
        return _assertion(passkey, challenge, WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV);
    }

    /// @dev Builds a WebAuthn assertion the way an authenticator does: the challenge goes into the
    ///      client data, and the key signs sha256(authenticatorData || sha256(clientDataJSON)).
    function _assertion(uint256 passkey, bytes32 challenge, bytes1 flags)
        internal
        pure
        returns (WebAuthn.WebAuthnAuth memory)
    {
        // rpIdHash (32) || flags (1) || signCount (4)
        bytes memory authenticatorData = abi.encodePacked(sha256("onchainid.test"), flags, bytes4(0));
        string memory clientDataJSON = string.concat(
            '{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(challenge)), '"}'
        );

        (bytes32 r, bytes32 s) =
            vm.signP256(passkey, sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON)))));
        // Only the low half of the curve order is accepted, as for secp256k1.
        if (uint256(s) > P256.N / 2) s = bytes32(P256.N - uint256(s));

        return WebAuthn.WebAuthnAuth({
            r: r,
            s: s,
            challengeIndex: 23,
            typeIndex: 1,
            authenticatorData: authenticatorData,
            clientDataJSON: clientDataJSON
        });
    }

}

contract Target {

    uint256 public count;

    function increment() external {
        count++;
    }

}

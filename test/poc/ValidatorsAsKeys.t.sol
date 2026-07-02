// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { MockStockECDSAValidator } from "../mocks/MockStockECDSAValidator.sol";
import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IAccount, PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import { MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { ERC7579Signature } from "contracts/modules/validators/ERC7579Signature.sol";

/// @notice PoC coverage for the "validators-as-keys" redesign. The three questions this
///         file answers:
///
///           1. Can a stock ERC-7579 validator — one with no ONCHAINID awareness, no
///              `keyHasPurpose` call, no `abi.encode(bytes signer, bytes sig)` wire
///              format — drop into a SmartAccount and pass `validateUserOp`?
///           2. Does the per-target rule now enforce authorization against the
///              validator address (via `hashAddress(validator)`), so ACTION-only
///              validators cannot self-target and MANAGEMENT validators can?
///           3. Does the ERC-1271 dispatch inherited from OZ (which routes on the
///              first-20-bytes-of-outer-signature module prefix) work end-to-end
///              alongside the userOp path?
contract ValidatorsAsKeysTest is OnchainIDSetup {

    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    MockStockECDSAValidator internal stock;

    // Fresh signer for the stock validator; kept separate from `david` (who is
    // still an ACTION key on alice) so the two paths can't accidentally overlap.
    address internal stockSigner;
    uint256 internal stockSignerPk;

    function setUp() public virtual override {
        super.setUp();
        (stockSigner, stockSignerPk) = makeAddrAndKey("stockSigner");
        stock = new MockStockECDSAValidator();
    }

    // --- helpers ---------------------------------------------------------

    function _packNonce(address validator, uint96 seq) internal pure returns (uint256) {
        return (uint256(uint160(validator)) << 96) | uint256(seq);
    }

    function _installStock(uint256 purpose) internal {
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(stock), abi.encodePacked(stockSigner));
        // Grant the validator the authorization purpose at the account layer. This is
        // the "validators-as-keys" wiring; the validator itself does not consult
        // ERC-734, so the account is the sole source of truth.
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(stock))), purpose, KeyTypes.MODULE);
        vm.stopPrank();
    }

    function _buildUserOp(address validator, address target, bytes memory innerCall)
        internal
        view
        returns (PackedUserOperation memory userOp, bytes32 userOpHash)
    {
        bytes memory executionCalldata = abi.encodePacked(target, uint256(0), innerCall);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), bytes32(0), executionCalldata);
        userOp = PackedUserOperation({
            sender: address(aliceIdentity),
            nonce: _packNonce(validator, 0),
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

    function _signStock(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(stockSignerPk, hash);
        return abi.encodePacked(r, s, v);
    }

    // --- tests -----------------------------------------------------------

    /// @notice Load-bearing proof: install a validator with zero ONCHAINID awareness,
    ///         sign a userOp against an external target, expect success.
    function test_stockValidator_dropIn_externalTargetSucceeds() public {
        _installStock(KeyPurposes.ACTION);

        PocCounter counter = new PocCounter();
        (PackedUserOperation memory userOp, bytes32 userOpHash) =
            _buildUserOp(address(stock), address(counter), abi.encodeCall(PocCounter.increment, ()));
        userOp.signature = _signStock(userOpHash);

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(
            result, ERC4337Utils.SIG_VALIDATION_SUCCESS, "stock validator (ACTION) must succeed on external target"
        );
    }

    /// @notice The strict per-target default still bites: an ACTION-only validator
    ///         cannot self-target `addKey`.
    function test_stockValidator_selfTargetFails_needsManagement() public {
        _installStock(KeyPurposes.ACTION);

        bytes memory innerCall = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", keccak256("poc-evil"), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );
        (PackedUserOperation memory userOp, bytes32 userOpHash) =
            _buildUserOp(address(stock), address(aliceIdentity), innerCall);
        userOp.signature = _signStock(userOpHash);

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED, "ACTION-only validator must not self-target addKey");
    }

    /// @notice Grant the validator MANAGEMENT and the same self-target userOp is now
    ///         authorized. Proves the purpose grant flows through unmodified.
    function test_stockValidator_selfTargetSucceeds_whenManagement() public {
        _installStock(KeyPurposes.MANAGEMENT);

        bytes memory innerCall = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", keccak256("poc-mgmt"), KeyPurposes.ACTION, KeyTypes.ECDSA
        );
        (PackedUserOperation memory userOp, bytes32 userOpHash) =
            _buildUserOp(address(stock), address(aliceIdentity), innerCall);
        userOp.signature = _signStock(userOpHash);

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_SUCCESS, "MANAGEMENT validator must be able to self-target");
    }

    /// @notice Regression: the legacy `ERC7579Signature` validator (installed by the
    ///         `OnchainIDSetup` fixture) still passes its 4337 path under the new
    ///         model. The wire format is unchanged; ACTION now lives on
    ///         `hashAddress(validator)` (granted by the fixture) rather than on
    ///         `keccak256(signer)`.
    function test_legacyValidator_worksUnderNewModel() public {
        PocCounter counter = new PocCounter();
        bytes memory innerCall = abi.encodeCall(PocCounter.increment, ());

        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), innerCall);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), bytes32(0), executionCalldata);
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(aliceIdentity),
            nonce: _packNonce(address(onchainidSetup.signatureValidator), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));

        // Legacy wire format: `abi.encode(bytes signer, bytes sig)`. Any EOA whose
        // signature the validator can verify is fine; the account-level gate is
        // now checked against the validator, not the signer.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(davidPk, userOpHash);
        userOp.signature = abi.encode(abi.encodePacked(david), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(
            result,
            ERC4337Utils.SIG_VALIDATION_SUCCESS,
            "legacy ERC7579Signature must still succeed under validators-as-keys"
        );
    }

    /// @notice ERC-1271 path. The account routes on the first-20-bytes-of-outer-signature
    ///         module prefix (OZ inherited `isValidSignature`). The stock validator
    ///         has zero coupling to ONCHAINID and returns the magic value on success.
    function test_1271_worksWithModulePrefixedSignature() public {
        _installStock(KeyPurposes.ACTION);

        bytes32 digest = keccak256("poc-1271-hash");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(stockSignerPk, digest);
        bytes memory innerSig = abi.encodePacked(r, s, v);
        bytes memory outerSig = abi.encodePacked(address(stock), innerSig);

        bytes4 magic = IERC1271(address(aliceIdentity)).isValidSignature(digest, outerSig);
        assertEq(magic, IERC1271.isValidSignature.selector, "stock validator 1271 dispatch must succeed");
    }

    /// @notice Registry hole closure. The legacy validator (installed by the fixture
    ///         with `david` as its authorized signer) must reject an unregistered EOA
    ///         even when the signature is cryptographically valid. Before the
    ///         per-account signer registry was added, ANY EOA producing a valid sig
    ///         over the digest passed the validator; the account-layer ACTION grant
    ///         then let them act on external targets. With the registry in place, the
    ///         membership check fails before we reach the account.
    function test_registry_unregisteredSignerFails() public {
        (address stranger, uint256 strangerPk) = makeAddrAndKey("stranger");

        PocCounter counter = new PocCounter();
        bytes memory innerCall = abi.encodeCall(PocCounter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), innerCall);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), bytes32(0), executionCalldata);
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(aliceIdentity),
            nonce: _packNonce(address(onchainidSetup.signatureValidator), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(strangerPk, userOpHash);
        userOp.signature = abi.encode(abi.encodePacked(stranger), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(
            result,
            ERC4337Utils.SIG_VALIDATION_FAILED,
            "unregistered signer must fail at the validator's membership check"
        );
    }

    /// @notice setSigner rotation. The account routes a MANAGEMENT-authorized userOp
    ///         through `execute(...)` that self-calls `validator.setSigner(newSigner)`,
    ///         swapping `david` for a fresh EOA. After rotation, a userOp signed by
    ///         `david` must fail and one signed by the new signer must succeed.
    function test_registry_setSignerRotatesCleanly() public {
        // Grant the fixture's validator MANAGEMENT so the self-target `setSigner` call
        // clears the strict-default per-target rule (self-target requires MANAGEMENT).
        vm.prank(alice);
        aliceIdentity.addKey(
            keccak256(abi.encodePacked(address(onchainidSetup.signatureValidator))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE
        );

        (address newSigner, uint256 newSignerPk) = makeAddrAndKey("newSigner");

        // Route through IKeyExecutor.execute (the KAM queue path) so the account
        // self-calls setSigner on the validator with `msg.sender == aliceIdentity`.
        vm.prank(alice);
        IKeyExecutor(address(aliceIdentity))
            .execute(
                address(onchainidSetup.signatureValidator),
                0,
                abi.encodeCall(ERC7579Signature.setSigner, (abi.encodePacked(newSigner)))
            );

        bytes memory stored = onchainidSetup.signatureValidator.signer(address(aliceIdentity));
        assertEq(keccak256(stored), keccak256(abi.encodePacked(newSigner)), "registry must reflect the rotated signer");

        // OLD signer (david) must now fail — no longer the authorized signer.
        {
            PocCounter counter = new PocCounter();
            bytes memory innerCall = abi.encodeCall(PocCounter.increment, ());
            (PackedUserOperation memory userOp, bytes32 userOpHash) =
                _buildUserOp(address(onchainidSetup.signatureValidator), address(counter), innerCall);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(davidPk, userOpHash);
            userOp.signature = abi.encode(abi.encodePacked(david), abi.encodePacked(r, s, v));

            vm.prank(ENTRY_POINT);
            uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
            assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED, "rotated-out signer must no longer be accepted");
        }

        // NEW signer must succeed.
        {
            PocCounter counter = new PocCounter();
            bytes memory innerCall = abi.encodeCall(PocCounter.increment, ());
            (PackedUserOperation memory userOp, bytes32 userOpHash) =
                _buildUserOp(address(onchainidSetup.signatureValidator), address(counter), innerCall);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(newSignerPk, userOpHash);
            userOp.signature = abi.encode(abi.encodePacked(newSigner), abi.encodePacked(r, s, v));

            vm.prank(ENTRY_POINT);
            uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
            assertEq(result, ERC4337Utils.SIG_VALIDATION_SUCCESS, "rotated-in signer must be accepted");
        }
    }

}

/// @notice PoC-local counter mock. Duplicated (rather than imported from SmartAccount.t.sol)
///         to keep this file self-contained.
contract PocCounter {

    uint256 public count;

    function increment() external {
        count++;
    }

}

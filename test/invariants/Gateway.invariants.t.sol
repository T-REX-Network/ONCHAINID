// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IdentityHelper } from "../helpers/IdentityHelper.sol";
import { Gateway } from "contracts/gateway/Gateway.sol";
import { Test } from "forge-std/Test.sol";

/// @notice Stateful invariants for the Gateway's owner-gated bookkeeping. The two storage
///         mappings (`approvedSigners`, `revokedSignatures`) are toggled by four
///         owner-only functions; the handler shadows them in a local ledger and the
///         invariants assert storage never diverges from the ledger across any reachable
///         sequence of calls. Config follows the [profile.default.invariant] in
///         foundry.toml (`runs=16 depth=16`) to keep default `forge test` fast; ramp via
///         `FOUNDRY_PROFILE=ci` for audit runs.
contract GatewayInvariants is Test {

    GatewayHandler internal handler;
    Gateway internal gateway;
    address internal gwOwner;

    function setUp() public {
        gwOwner = address(this);
        address deployer = makeAddr("gwInvDeployer");

        vm.prank(deployer);
        IdentityHelper.OnchainIDSetup memory setup = IdentityHelper.deployFactory(deployer);

        // Gateway with no preloaded signers — the handler will toggle them.
        address[] memory none = new address[](0);
        gateway = new Gateway(address(setup.idFactory), none, gwOwner);

        handler = new GatewayHandler(gateway, gwOwner);
        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = GatewayHandler.handler_approveSigner.selector;
        selectors[1] = GatewayHandler.handler_revokeSigner.selector;
        selectors[2] = GatewayHandler.handler_revokeSignature.selector;
        selectors[3] = GatewayHandler.handler_approveSignature.selector;
        targetSelector(FuzzSelector({ addr: address(handler), selectors: selectors }));
    }

    /// @notice GW1: `approvedSigners` storage equals the handler ledger for every address
    ///         in the pool. Catches any divergence between the contract's view and the
    ///         expected post-toggle state.
    function invariant_approvedSignerStorageAgreesWithLedger() public view {
        address[] memory pool = handler.signerPool();
        for (uint256 i = 0; i < pool.length; i++) {
            assertEq(
                gateway.approvedSigners(pool[i]),
                handler.expectedApproved(pool[i]),
                "approvedSigners storage diverged from handler ledger"
            );
        }
    }

    /// @notice GW2: `revokedSignatures` storage equals the handler ledger for every
    ///         signature blob in the pool.
    function invariant_revokedSignatureStorageAgreesWithLedger() public view {
        uint256 len = handler.sigPoolLength();
        for (uint256 i = 0; i < len; i++) {
            assertEq(
                gateway.revokedSignatures(handler.sigAt(i)),
                handler.expectedRevoked(i),
                "revokedSignatures storage diverged from handler ledger"
            );
        }
    }

    /// @notice GW3: `idFactory` is declared `immutable` — this invariant exists to flag any
    ///         future codegen change (e.g. accidental removal of `immutable`) that would
    ///         let the factory anchor drift under the handler's toggle stream.
    function invariant_idFactoryNeverChanges() public view {
        assertEq(address(gateway.idFactory()), handler.frozenIdFactory(), "Gateway.idFactory must remain anchored");
    }

    /// @notice GW4: the only way for ownership to change is `Ownable.transferOwnership`,
    ///         which the handler does not invoke. Catches any path that would let an
    ///         owner-gated call mutate ownership as a side-effect.
    function invariant_ownerNeverChanges() public view {
        assertEq(gateway.owner(), gwOwner, "Gateway owner drifted under handler-only state changes");
    }

}

/// @notice Handler that drives the four owner-only toggles. State space is intentionally
///         small (4 signers × 4 signatures) so the default low-depth invariant config still
///         explores meaningful re-approve / re-revoke transitions instead of burning depth
///         on rejected inputs.
contract GatewayHandler is Test {

    Gateway internal immutable gateway;
    address internal immutable owner;
    address internal immutable _frozenIdFactory;

    address[] internal _signerPool;
    bytes[] internal _sigPool;

    mapping(address => bool) internal _approved;
    mapping(uint256 => bool) internal _revoked;

    constructor(Gateway _gateway, address _owner) {
        gateway = _gateway;
        owner = _owner;
        _frozenIdFactory = address(_gateway.idFactory());

        _signerPool.push(makeAddr("gwInv-signer-0"));
        _signerPool.push(makeAddr("gwInv-signer-1"));
        _signerPool.push(makeAddr("gwInv-signer-2"));
        _signerPool.push(makeAddr("gwInv-signer-3"));

        _sigPool.push(hex"00");
        _sigPool.push(hex"01");
        _sigPool.push(hex"deadbeef");
        _sigPool.push(hex"feedface");
    }

    /// @dev Try/catch swallows the contract's idempotency reverts (already-approved /
    ///      already-not-approved). The ledger is only updated on successful mutation, so
    ///      storage and ledger stay in lockstep regardless of which branch the runner took.
    function handler_approveSigner(uint256 idx) public {
        idx = bound(idx, 0, _signerPool.length - 1);
        address s = _signerPool[idx];
        vm.prank(owner);
        try gateway.approveSigner(s) {
            _approved[s] = true;
        } catch { }
    }

    function handler_revokeSigner(uint256 idx) public {
        idx = bound(idx, 0, _signerPool.length - 1);
        address s = _signerPool[idx];
        vm.prank(owner);
        try gateway.revokeSigner(s) {
            _approved[s] = false;
        } catch { }
    }

    function handler_revokeSignature(uint256 idx) public {
        idx = bound(idx, 0, _sigPool.length - 1);
        vm.prank(owner);
        try gateway.revokeSignature(_sigPool[idx]) {
            _revoked[idx] = true;
        } catch { }
    }

    function handler_approveSignature(uint256 idx) public {
        idx = bound(idx, 0, _sigPool.length - 1);
        vm.prank(owner);
        try gateway.approveSignature(_sigPool[idx]) {
            _revoked[idx] = false;
        } catch { }
    }

    // ---- views ----

    function signerPool() external view returns (address[] memory) {
        return _signerPool;
    }

    function sigPoolLength() external view returns (uint256) {
        return _sigPool.length;
    }

    function sigAt(uint256 i) external view returns (bytes memory) {
        return _sigPool[i];
    }

    function expectedApproved(address s) external view returns (bool) {
        return _approved[s];
    }

    function expectedRevoked(uint256 idx) external view returns (bool) {
        return _revoked[idx];
    }

    function frozenIdFactory() external view returns (address) {
        return _frozenIdFactory;
    }

}

// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { MockERC7786Gateway } from "../mocks/MockERC7786Gateway.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice An identity's address is known before it is deployed (CREATE3), so it can be linked
///         as a wallet of another identity first. Deploying it must take the address back.
contract IdentityLinkedBeforeDeployTest is OnchainIDSetup {

    string internal constant VICTIM_SALT = "victim";

    address internal victim;
    address internal squatter;
    address internal predictedIdentity;
    address internal squattingIdentity;

    function setUp() public override {
        super.setUp();
        victim = makeAddr("victim");
        squatter = makeAddr("squatter");

        predictedIdentity = _predictVictimIdentity(VICTIM_SALT);

        // INDIVIDUAL is open to anyone through createIdentityFor in the test setup.
        vm.prank(squatter);
        squattingIdentity = onchainidSetup.idFactory
            .createIdentityFor(predictedIdentity, IdentityTypes.INDIVIDUAL, "squat", _managementKeys(predictedIdentity));
    }

    function test_deploy_revokesALinkMadeBeforeDeploy() public {
        bytes memory predictedAccount = _account(predictedIdentity);
        assertEq(onchainidSetup.idFactory.getAccountsCount(squattingIdentity), 1);

        vm.expectEmit(address(onchainidSetup.idFactory));
        emit IIdentityFactory.AccountRevoked(predictedAccount, squattingIdentity, victim);
        vm.prank(victim);
        address deployed =
            onchainidSetup.idFactory.createIdentity(IdentityTypes.INDIVIDUAL, VICTIM_SALT, _managementKeys(victim));

        assertEq(deployed, predictedIdentity);
        assertEq(onchainidSetup.idFactory.getAccountsCount(squattingIdentity), 0);
        assertEq(onchainidSetup.idFactory.getIdentity(predictedAccount), predictedIdentity);
        (address resolved, IIdentityFactory.AccountStatus status) =
            onchainidSetup.idFactory.getIdentityIncludingRevoked(predictedAccount);
        assertEq(resolved, predictedIdentity);
        assertEq(uint256(status), uint256(IIdentityFactory.AccountStatus.Active));
    }

    function test_deploy_resolvesToItselfWhenTheEarlierLinkWasAlreadyRevoked() public {
        bytes memory predictedAccount = _account(predictedIdentity);
        vm.prank(squattingIdentity);
        onchainidSetup.idFactory.revokeAccount(predictedAccount);

        vm.prank(victim);
        onchainidSetup.idFactory.createIdentity(IdentityTypes.INDIVIDUAL, VICTIM_SALT, _managementKeys(victim));

        assertEq(onchainidSetup.idFactory.getAccountsCount(squattingIdentity), 0);
        assertEq(onchainidSetup.idFactory.getIdentity(predictedAccount), predictedIdentity);
    }

    /// @notice A single-binding identity keeps its one binding for good, even after its account
    ///         deploys as an identity and leaves its account set.
    function test_linkAccount_RevertWhen_ASingleBindingIdentityLostItsAccountToADeploy() public {
        address bindingIdentity = _bindSmartContractIdentityToPredictedAddressThenDeploy();

        bytes memory davidAccount = _account(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(davidAccount);
        bytes memory signature = _signLink(davidPk, davidAccount, bindingIdentity, nonce, expiry);

        vm.prank(bindingIdentity);
        vm.expectRevert(abi.encodeWithSelector(Errors.CannotLinkToAssetIdentity.selector, bindingIdentity));
        onchainidSetup.idFactory.linkAccount(davidAccount, signature, nonce, expiry);
    }

    /// @notice Same through the cross-chain path. Declining the proposal still works.
    function test_settlePendingCrossChainLink_RevertWhen_ASingleBindingIdentityLostItsAccountToADeploy() public {
        address bindingIdentity = _bindSmartContractIdentityToPredictedAddressThenDeploy();

        MockERC7786Gateway gateway = new MockERC7786Gateway();
        bytes2 solanaChainType = 0x0001;
        bytes memory solanaChainReference = hex"01";
        vm.prank(deployer);
        onchainidSetup.idFactory.setTrustedGateway(address(gateway), solanaChainType, solanaChainReference, true);
        bytes memory solanaWallet = InteroperableAddress.formatV1(
            solanaChainType, solanaChainReference, abi.encodePacked(bytes32(uint256(uint160(david))))
        );
        uint256 expiry = block.timestamp + 1 hours;
        gateway.deliver(
            address(onchainidSetup.idFactory),
            bytes32(uint256(1)),
            solanaWallet,
            abi.encode(solanaWallet, bindingIdentity, expiry)
        );

        vm.prank(bindingIdentity);
        vm.expectRevert(abi.encodeWithSelector(Errors.CannotLinkToAssetIdentity.selector, bindingIdentity));
        onchainidSetup.idFactory.settlePendingCrossChainLink(solanaWallet, true);

        vm.prank(bindingIdentity);
        onchainidSetup.idFactory.settlePendingCrossChainLink(solanaWallet, false);
        assertEq(onchainidSetup.idFactory.getAccountsCount(bindingIdentity), 0);
    }

    /// @dev A SMART_CONTRACT identity (single binding) is created with the victim's predicted
    ///      address as its one account, then the victim deploys and takes the address back.
    function _bindSmartContractIdentityToPredictedAddressThenDeploy() internal returns (address bindingIdentity) {
        string memory salt = "contractVictim";
        address predicted = _predictVictimIdentity(salt);
        vm.prank(deployer);
        bindingIdentity = onchainidSetup.idFactory
            .createIdentityFor(predicted, IdentityTypes.SMART_CONTRACT, "binding", _managementKeys(david));

        vm.prank(victim);
        onchainidSetup.idFactory.createIdentity(IdentityTypes.INDIVIDUAL, salt, _managementKeys(victim));
        assertEq(onchainidSetup.idFactory.getAccountsCount(bindingIdentity), 0);
    }

    /// @dev The address the victim's deploy with `salt` lands at. The deploy is rolled back, and
    ///      the rollback also resets this contract's storage, so the address comes back in a local.
    function _predictVictimIdentity(string memory salt) internal returns (address predicted) {
        uint256 beforeDeploy = vm.snapshotState();
        vm.prank(victim);
        predicted = onchainidSetup.idFactory.createIdentity(IdentityTypes.INDIVIDUAL, salt, _managementKeys(victim));
        vm.revertToState(beforeDeploy);
    }

    function _signLink(uint256 signerPk, bytes memory account, address identity, uint256 nonce, uint256 expiry)
        internal
        view
        returns (bytes memory)
    {
        bytes32 linkTypehash = keccak256("LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)");
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("IdentityFactory")),
                keccak256(bytes("1")),
                block.chainid,
                address(onchainidSetup.idFactory)
            )
        );
        bytes32 structHash = keccak256(abi.encode(linkTypehash, keccak256(account), identity, nonce, expiry));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(signerPk, MessageHashUtils.toTypedDataHash(domainSeparator, structHash));
        return abi.encodePacked(r, s, v);
    }

    function _account(address wallet) internal view returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(block.chainid, wallet);
    }

    function _managementKeys(address wallet) internal pure returns (Structs.KeyParam[] memory keys) {
        keys = new Structs.KeyParam[](1);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(wallet)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(wallet),
            clientData: ""
        });
    }

}

use crate::rs_contracts::contracts::tool::utils::is_permssion_contract;
use cita_vm::evm::InterpreterParams;
use cita_vm::evm::InterpreterResult;
use common_types::errors::ContractError;
use common_types::reserved_addresses;

use cita_types::Address;
use common_types::context::Context;
use std::sync::Arc;

use crate::rs_contracts::contracts::contract::Contract;
use crate::rs_contracts::storage::db_contracts::ContractsDB;

use crate::rs_contracts::contracts::sys::{
    AdminContract, AutoContract, BatchTx, EmergContract, NodeStore, PriceContract, QuotaContract,
    SystemContract, VersionContract,
};
use crate::rs_contracts::contracts::{group::GroupStore, perm::PermStore, role::RoleStore};

use cita_trie::DB;
use cita_vm::state::State;
use std::cell::RefCell;
use std::collections::BTreeMap;

pub struct ContractsFactory<B> {
    // contracts: HashMap<Address, Box<Contract>>,
    state: Arc<RefCell<State<B>>>,
    contracts_db: Arc<ContractsDB>,
    admin_contract: AdminContract,
    price_contract: PriceContract,
    perm_store: PermStore,
    emerg_contract: EmergContract,
    system_contract: SystemContract,
    nodes_store: NodeStore,
    quota_contract: QuotaContract,
    version_contract: VersionContract,
    group_store: GroupStore,
    auto_exec_contract: AutoContract,
    batch_tx: BatchTx,
    role_store: RoleStore,
}

impl<B: DB> ContractsFactory<B> {
    pub fn register(&mut self, address: Address, contract: String) {
        trace!(
            "Register system contract address {:?} contract {:?}",
            address,
            contract
        );
        if address == Address::from(reserved_addresses::ADMIN) {
            AdminContract::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::PRICE_MANAGEMENT) {
            PriceContract::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::VERSION_MANAGEMENT) {
            VersionContract::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::EMERGENCY_INTERVENTION) {
            EmergContract::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::SYS_CONFIG) {
            SystemContract::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::NODE_MANAGER) {
            NodeStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::QUOTA_MANAGER) {
            QuotaContract::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::GROUP) {
            GroupStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::AUTO_EXEC) {
            AutoContract::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::ROLE_MANAGEMENT) {
            RoleStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::BATCH_TX) {
            trace!("Init batch tx system contract");
        }
    }

    pub fn register_perms(&mut self, admin: Address, perm_contracts: BTreeMap<Address, String>) {
        trace!("Register permission contract {:?}", perm_contracts);
        PermStore::init(admin, perm_contracts, self.contracts_db.clone());
    }
}

impl<B: DB + 'static> ContractsFactory<B> {
    pub fn new(state: Arc<RefCell<State<B>>>, contracts_db: Arc<ContractsDB>) -> Self {
        ContractsFactory {
            state: state,
            contracts_db: contracts_db,
            admin_contract: AdminContract::default(),
            price_contract: PriceContract::default(),
            perm_store: PermStore::default(),
            emerg_contract: EmergContract::default(),
            system_contract: SystemContract::default(),
            nodes_store: NodeStore::default(),
            quota_contract: QuotaContract::default(),
            version_contract: VersionContract::default(),
            group_store: GroupStore::default(),
            auto_exec_contract: AutoContract::default(),
            batch_tx: BatchTx::default(),
            role_store: RoleStore::default(),
        }
    }

    pub fn is_rs_contract(&self, addr: &Address) -> bool {
        if *addr == Address::from(reserved_addresses::ADMIN)
            || *addr == Address::from(reserved_addresses::PRICE_MANAGEMENT)
            || *addr == Address::from(reserved_addresses::PERMISSION_MANAGEMENT)
            || *addr == Address::from(reserved_addresses::AUTHORIZATION)
            || *addr == Address::from(reserved_addresses::EMERGENCY_INTERVENTION)
            || *addr == Address::from(reserved_addresses::SYS_CONFIG)
            || *addr == Address::from(reserved_addresses::QUOTA_MANAGER)
            || *addr == Address::from(reserved_addresses::NODE_MANAGER)
            || *addr == Address::from(reserved_addresses::VERSION_MANAGEMENT)
            || *addr == Address::from(reserved_addresses::GROUP)
            || *addr == Address::from(reserved_addresses::GROUP_MANAGEMENT)
            || *addr == Address::from(reserved_addresses::AUTO_EXEC)
            || *addr == Address::from(reserved_addresses::BATCH_TX)
            || *addr == Address::from(reserved_addresses::ROLE_MANAGEMENT)
            || *addr == Address::from(reserved_addresses::ROLE_AUTH)
            || is_permssion_contract(*addr)
        {
            return true;
        }
        false
    }

    pub fn works(
        &self,
        params: &InterpreterParams,
        context: &Context,
    ) -> Result<InterpreterResult, ContractError> {
        if params.contract.code_address == Address::from(reserved_addresses::ADMIN) {
            return self.admin_contract.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address
            == Address::from(reserved_addresses::PRICE_MANAGEMENT)
        {
            return self.price_contract.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address
            == Address::from(reserved_addresses::VERSION_MANAGEMENT)
        {
            return self.version_contract.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address
            == Address::from(reserved_addresses::EMERGENCY_INTERVENTION)
        {
            return self.emerg_contract.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address == Address::from(reserved_addresses::SYS_CONFIG) {
            return self.system_contract.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address == Address::from(reserved_addresses::NODE_MANAGER) {
            return self.nodes_store.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address == Address::from(reserved_addresses::AUTO_EXEC) {
            return self.auto_exec_contract.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address == Address::from(reserved_addresses::BATCH_TX) {
            return self.batch_tx.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address == Address::from(reserved_addresses::QUOTA_MANAGER) {
            return self.quota_contract.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address == Address::from(reserved_addresses::GROUP)
            || params.contract.code_address == Address::from(reserved_addresses::GROUP_MANAGEMENT)
        {
            return self.group_store.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address == Address::from(reserved_addresses::ROLE_MANAGEMENT)
            || params.contract.code_address == Address::from(reserved_addresses::ROLE_AUTH)
        {
            return self.role_store.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address
            == Address::from(reserved_addresses::PERMISSION_MANAGEMENT)
            || params.contract.code_address == Address::from(reserved_addresses::AUTHORIZATION)
            || is_permssion_contract(params.contract.code_address)
        {
            trace!("This a permission related contract");
            return self.perm_store.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        }

        return Err(ContractError::AdminError(String::from(
            "not a valid address",
        )));
    }
}

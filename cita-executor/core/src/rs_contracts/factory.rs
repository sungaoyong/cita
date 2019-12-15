use cita_trie::DB;
use cita_types::Address;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::rs_contracts::contracts::contract::Contract;
use crate::rs_contracts::storage::db_contracts::ContractsDB;

use crate::rs_contracts::contracts::sys::{
    AdminStore, AutoStore, BatchTx, EmergStore, NodeStore, PriceStore, QuotaStore, SystemStore,
    VersionStore,
};
use crate::rs_contracts::contracts::{group::GroupStore, perm::PermStore, role::RoleStore};

use crate::rs_contracts::contracts::tool::check;
use cita_vm::evm::{InterpreterParams, InterpreterResult};
use cita_vm::state::State;
use common_types::{context::Context, errors::ContractError, reserved_addresses};

pub struct ContractsFactory<B> {
    // contracts: HashMap<Address, Box<Contract>>,
    state: Arc<RefCell<State<B>>>,
    contracts_db: Arc<ContractsDB>,
    admin_store: AdminStore,
    price_store: PriceStore,
    perm_store: PermStore,
    emerg_store: EmergStore,
    system_store: SystemStore,
    nodes_store: NodeStore,
    quota_store: QuotaStore,
    version_store: VersionStore,
    group_store: GroupStore,
    auto_store: AutoStore,
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
            AdminStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::PRICE_MANAGEMENT) {
            PriceStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::VERSION_MANAGEMENT) {
            VersionStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::EMERGENCY_INTERVENTION) {
            EmergStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::SYS_CONFIG) {
            SystemStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::NODE_MANAGER) {
            NodeStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::QUOTA_MANAGER) {
            QuotaStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::GROUP) {
            GroupStore::init(contract, self.contracts_db.clone());
        } else if address == Address::from(reserved_addresses::AUTO_EXEC) {
            AutoStore::init(contract, self.contracts_db.clone());
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
            admin_store: AdminStore::default(),
            price_store: PriceStore::default(),
            perm_store: PermStore::default(),
            emerg_store: EmergStore::default(),
            system_store: SystemStore::default(),
            nodes_store: NodeStore::default(),
            quota_store: QuotaStore::default(),
            version_store: VersionStore::default(),
            group_store: GroupStore::default(),
            auto_store: AutoStore::default(),
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
            || check::check_is_permssion_contract(*addr)
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
            return self.admin_store.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address
            == Address::from(reserved_addresses::PRICE_MANAGEMENT)
        {
            return self.price_store.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address
            == Address::from(reserved_addresses::VERSION_MANAGEMENT)
        {
            return self.version_store.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address
            == Address::from(reserved_addresses::EMERGENCY_INTERVENTION)
        {
            return self.emerg_store.execute(
                &params,
                context,
                self.contracts_db.clone(),
                self.state.clone(),
            );
        } else if params.contract.code_address == Address::from(reserved_addresses::SYS_CONFIG) {
            return self.system_store.execute(
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
            return self.auto_store.execute(
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
            return self.quota_store.execute(
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
            || check::check_is_permssion_contract(params.contract.code_address)
        {
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

use cita_trie::DB;
use cita_types::Address;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::rs_contracts::contracts::contract::Contract;
use crate::rs_contracts::contracts::perm::BUILD_IN_PERMS;
use crate::rs_contracts::storage::db_contracts::ContractsDB;

use crate::rs_contracts::contracts::sys::{
    AdminStore, AutoStore, BatchTx, EmergStore, NodeStore, PriceStore, QuotaStore, SystemStore,
    VersionStore,
};
use crate::rs_contracts::contracts::{group::GroupStore, perm::PermStore, role::RoleStore};

use cita_vm::state::State;
use common_types::{context::Context, errors::ContractError, reserved_addresses};

pub struct ContractsFactory<B> {
    contracts: BTreeMap<Address, Box<dyn Contract<B>>>,
}

impl<B: DB> ContractsFactory<B> {
    pub fn register(&mut self, address: Address, contract: Box<dyn Contract<B>>) {
        trace!("Register system contract address {:?}", address);
        self.contracts.insert(address, contract);
    }
}

impl<B: DB + 'static> ContractsFactory<B> {
    pub fn new(_state: Arc<RefCell<State<B>>>, _contracts_db: Arc<ContractsDB>) -> Self {
        let mut rs_contracts: BTreeMap<Address, Box<dyn Contract<B>>> = BTreeMap::new();
        rs_contracts.insert(
            Address::from(reserved_addresses::ADMIN),
            Box::new(AdminStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::PRICE_MANAGEMENT),
            Box::new(PriceStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::VERSION_MANAGEMENT),
            Box::new(VersionStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::EMERGENCY_INTERVENTION),
            Box::new(EmergStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::SYS_CONFIG),
            Box::new(SystemStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::NODE_MANAGER),
            Box::new(NodeStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::QUOTA_MANAGER),
            Box::new(QuotaStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::GROUP),
            Box::new(GroupStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::GROUP_MANAGEMENT),
            Box::new(GroupStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::AUTO_EXEC),
            Box::new(AutoStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::ROLE_MANAGEMENT),
            Box::new(RoleStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::ROLE_AUTH),
            Box::new(RoleStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::BATCH_TX),
            Box::new(BatchTx::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::PERMISSION_MANAGEMENT),
            Box::new(PermStore::default()),
        );
        rs_contracts.insert(
            Address::from(reserved_addresses::AUTHORIZATION),
            Box::new(PermStore::default()),
        );

        for p in BUILD_IN_PERMS.iter() {
            rs_contracts.insert(Address::from(*p), Box::new(PermStore::default()));
        }

        ContractsFactory {
            contracts: rs_contracts,
        }
    }

    pub fn get_contract(&self, addr: &Address) -> Option<Box<dyn Contract<B>>> {
        if let Some(contract) = self.contracts.get(addr) {
            Some(contract.create())
        } else {
            None
        }
    }
}

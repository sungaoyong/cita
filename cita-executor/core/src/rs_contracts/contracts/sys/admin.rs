use crate::rs_contracts::contracts::tool::{extract_to_u32, get_latest_key};
use crate::rs_contracts::contracts::Contract;

use cita_types::{Address, H256};
use cita_vm::evm::{InterpreterParams, InterpreterResult, Log};
use common_types::context::Context;
use common_types::errors::ContractError;

use crate::rs_contracts::contracts::perm::PermStore;
use crate::rs_contracts::storage::db_contracts::ContractsDB;
use crate::rs_contracts::storage::db_trait::{DataBase, DataCategory};

use cita_trie::DB;
use cita_vm::state::State;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use tiny_keccak::keccak256;

use crate::contracts::tools::method;

lazy_static! {
    static ref GET_ADMIN: u32 = method::encode_to_u32(b"admin()");
    static ref IS_ADMIN: u32 = method::encode_to_u32(b"isAdmin(address)");
    static ref UPDATE_ADMIN: u32 = method::encode_to_u32(b"update(address)");
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AdminStore {
    pub contracts: BTreeMap<u64, Option<String>>,
}

impl AdminStore {
    pub fn init(str: String, contracts_db: Arc<ContractsDB>) -> Self {
        let mut a = AdminStore::default();
        a.contracts.insert(0, Some(str));
        let s = serde_json::to_string(&a).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"admin".to_vec(),
            s.as_bytes().to_vec(),
        );
        a
    }

    pub fn get_latest_item(
        &self,
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<AdminStore>, Option<Admin>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"admin".to_vec())
            .expect("get store error")
        {
            let contract_map: AdminStore = serde_json::from_slice(&store).unwrap();
            let keys: Vec<_> = contract_map.contracts.keys().collect();
            let latest_key = get_latest_key(current_height, keys.clone());
            trace!(
                "Contract get_latest_key: current_height {:?}, keys {:?}, latest_key {:?}",
                current_height,
                keys,
                latest_key
            );

            let bin = contract_map
                .contracts
                .get(&(current_height as u64))
                .or(contract_map.contracts.get(&latest_key))
                .expect("get concrete contract error");
            let latest_item: Admin = serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            trace!("Contract latest item {:?}", latest_item);

            return (Some(contract_map), Some(latest_item));
        }
        (None, None)
    }
}

impl<B: DB> Contract<B> for AdminStore {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - Admin - enter execute");
        let (contract_map, latest_item) =
            self.get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_item) {
            (Some(mut contract_map), Some(mut latest_item)) => {
                trace!(
                    "System contracts - admin - params {:?}, input {:?}",
                    params.read_only,
                    params.input
                );

                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        sig if sig == *GET_ADMIN => latest_item.get_admin(),
                        sig if sig == *IS_ADMIN => latest_item.is_admin(params),
                        sig if sig == *UPDATE_ADMIN => latest_item.update(
                            params,
                            context,
                            contracts_db.clone(),
                            state.clone(),
                            &mut updated,
                        ),
                        _ => panic!("Invalid function signature".to_owned()),
                    });

                // update contract db
                if result.is_ok() && updated {
                    let new_item = latest_item;
                    let str = serde_json::to_string(&new_item).unwrap();
                    let updated_hash = keccak256(&str.as_bytes().to_vec());

                    // update state
                    let _ = state
                        .borrow_mut()
                        .set_storage(
                            &params.contract.code_address,
                            H256::from(context.block_number),
                            H256::from(updated_hash),
                        )
                        .expect("state set storage error");
                    contract_map
                        .contracts
                        .insert(context.block_number, Some(str));

                    let map_str = serde_json::to_string(&contract_map).unwrap();
                    let _ = contracts_db.insert(
                        DataCategory::Contracts,
                        b"admin".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );
                }
                return result;
            }
            _ => Err(ContractError::Internal("params errors".to_owned())),
        }
    }

    fn create(&self) -> Box<dyn Contract<B>> {
        Box::new(AdminStore::default())
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Admin {
    admin: Address,
}

impl Admin {
    pub fn new(admin: Address) -> Self {
        Admin { admin: admin }
    }

    fn get_admin(&self) -> Result<InterpreterResult, ContractError> {
        trace!("Admin contract: get_admin");
        return Ok(InterpreterResult::Normal(
            H256::from(self.admin).0.to_vec(),
            0,
            vec![],
        ));
    }

    fn update<B: DB>(
        &mut self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
        changed: &mut bool,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Admin contract: update");
        let param_address = Address::from_slice(&params.input[16..36]);
        // only admin can invoke
        if self.only_admin(params.sender) {
            // update permission
            PermStore::update_admin_permissions(
                params,
                context,
                self.admin,
                param_address,
                contracts_db.clone(),
                state.clone(),
            );

            self.admin = param_address;

            let mut logs = Vec::new();
            let mut topics = Vec::new();
            let signature = "AdminUpdated(address,address,address)".as_bytes();
            topics.push(H256::from(keccak256(signature)));
            topics.push(H256::from(param_address));
            topics.push(H256::from(self.admin));
            topics.push(H256::from(params.sender));
            let log = Log(param_address, topics, vec![]);
            logs.push(log);

            *changed = true;
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                logs,
            ));
        }

        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    fn is_admin(&self, params: &InterpreterParams) -> Result<InterpreterResult, ContractError> {
        trace!("Admin contract: is_admin");
        let param_address = Address::from_slice(&params.input[16..36]);
        if param_address == self.admin {
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        } else {
            return Ok(InterpreterResult::Normal(
                H256::from(0).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }
    }

    pub fn only_admin(&self, sender: Address) -> bool {
        if sender.to_vec() == self.admin.to_vec() {
            return true;
        }
        false
    }
}

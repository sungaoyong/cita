use crate::rs_contracts::contracts::tool::check;
use crate::rs_contracts::contracts::tool::{extract_to_u32, get_latest_key};

use cita_types::{H256, U256};
use cita_vm::evm::{InterpreterParams, InterpreterResult};
use common_types::context::Context;
use common_types::errors::ContractError;

use crate::rs_contracts::contracts::Contract;
use crate::rs_contracts::storage::db_contracts::ContractsDB;
use crate::rs_contracts::storage::db_trait::DataBase;
use crate::rs_contracts::storage::db_trait::DataCategory;

use cita_trie::DB;
use cita_vm::state::State;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use tiny_keccak::keccak256;

use crate::contracts::tools::method;
lazy_static! {
    static ref SET_VERSION: u32 = method::encode_to_u32(b"setVersion(uint32)");
    static ref GET_VERSION: u32 = method::encode_to_u32(b"getVersion()");
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct VersionStore {
    pub contracts: BTreeMap<u64, Option<String>>,
}

impl VersionStore {
    pub fn init(str: String, contracts_db: Arc<ContractsDB>) -> Self {
        let mut a = VersionStore::default();
        a.contracts.insert(0, Some(str));
        let s = serde_json::to_string(&a).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"version".to_vec(),
            s.as_bytes().to_vec(),
        );
        a
    }

    pub fn get_latest_item(
        &self,
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<VersionStore>, Option<Version>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"version".to_vec())
            .expect("get store error")
        {
            let contract_map: VersionStore = serde_json::from_slice(&store).unwrap();
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
            let latest_item: Version = serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            trace!("Contract latest item {:?}", latest_item);

            return (Some(contract_map), Some(latest_item));
        }
        (None, None)
    }
}

impl<B: DB> Contract<B> for VersionStore {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - price - enter execute");
        let (contract_map, latest_item) =
            self.get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_item) {
            (Some(mut contract_map), Some(mut latest_item)) => {
                trace!(
                    "System contracts - version - params input {:?}",
                    params.input
                );
                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        sig if sig == *GET_VERSION => latest_item.get_version(),
                        sig if sig == *SET_VERSION => latest_item.set_version(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        _ => panic!("Invalid function signature".to_owned()),
                    });

                if result.is_ok() & updated {
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
                        b"version".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );

                    // debug information, can be ommited
                    // let bin_map = contracts_db
                    //     .get(DataCategory::Contracts, b"version".to_vec())
                    //     .unwrap();
                    // let str = String::from_utf8(bin_map.unwrap()).unwrap();
                    // let contracts: VersionStore = serde_json::from_str(&str).unwrap();
                    // trace!("System contract version {:?} after update.", contracts);
                }
                return result;
            }
            _ => Err(ContractError::Internal("params error".to_owned())),
        }
    }

    fn create(&self) -> Box<dyn Contract<B>> {
        Box::new(VersionStore::default())
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Version {
    version: U256,
}

impl Version {
    pub fn new(version: U256) -> Self {
        Version { version }
    }

    pub fn set_version(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Version contract: set_version");
        let param_version = U256::from(&params.input[16..36]);
        // Note: Only admin can change quota price
        if check::only_admin(params, context, contracts_db.clone()).expect("only admin can do it")
            && param_version == self.version + 1
        {
            self.version = param_version;
            *changed = true;
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn get_version(&self) -> Result<InterpreterResult, ContractError> {
        trace!("Version contract: get_version");
        return Ok(InterpreterResult::Normal(
            H256::from(self.version).to_vec(),
            0,
            vec![],
        ));
    }
}

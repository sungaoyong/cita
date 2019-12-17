use crate::rs_contracts::contracts::tool::check;
use crate::rs_contracts::contracts::tool::{extract_to_u32, get_latest_key, h256_to_bool};

use cita_types::H256;
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
    static ref SET_STATE: u32 = method::encode_to_u32(b"setState(bool)");
    static ref GET_STATE: u32 = method::encode_to_u32(b"state()");
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct EmergStore {
    pub contracts: BTreeMap<u64, Option<String>>,
}

impl EmergStore {
    pub fn init(str: String, contracts_db: Arc<ContractsDB>) -> Self {
        let mut a = EmergStore::default();
        a.contracts.insert(0, Some(str));
        let s = serde_json::to_string(&a).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"emerg".to_vec(),
            s.as_bytes().to_vec(),
        );
        a
    }

    pub fn get_latest_item(
        &self,
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<EmergStore>, Option<EmergencyIntervention>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"emerg".to_vec())
            .expect("get store error")
        {
            let contract_map: EmergStore = serde_json::from_slice(&store).unwrap();
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

            let latest_item: EmergencyIntervention =
                serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            trace!("Contract latest item {:?}", latest_item);
            return (Some(contract_map), Some(latest_item));
        }
        (None, None)
    }
}

impl<B: DB> Contract<B> for EmergStore {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - emerg - enter execute");
        let (contract_map, latest_item) =
            self.get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_item) {
            (Some(mut contract_map), Some(mut latest_item)) => {
                trace!("System contracts - emerg - params input {:?}", params.input);
                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        sig if sig == *GET_STATE => latest_item.get_state(),
                        sig if sig == *SET_STATE => latest_item.set_state(
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
                        b"emerg".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );
                }
                return result;
            }
            _ => Err(ContractError::Internal("params error".to_owned())),
        }
    }

    fn create(&self) -> Box<dyn Contract<B>> {
        Box::new(EmergStore::default())
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct EmergencyIntervention {
    state: bool,
}

impl EmergencyIntervention {
    pub fn new(state: bool) -> Self {
        EmergencyIntervention { state }
    }

    pub fn set_state(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Emerg: set_state");
        let param_state = h256_to_bool(H256::from(&params.input[4..]));
        // Note: Only admin can change quota price
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin")
            && param_state != self.state
        {
            self.state = param_state;
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

    pub fn get_state(&self) -> Result<InterpreterResult, ContractError> {
        trace!("Emerg: get_state");
        if self.state {
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                0,
                vec![],
            ));
        } else {
            return Ok(InterpreterResult::Normal(
                H256::from(0).0.to_vec(),
                0,
                vec![],
            ));
        }
    }
}

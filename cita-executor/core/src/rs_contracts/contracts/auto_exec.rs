use super::check;
use super::utils::{extract_to_u32, get_latest_key};

use cita_types::{Address, H160, H256, U256};
use cita_vm::evm::{InterpreterParams, InterpreterResult};
use common_types::context::Context;
use common_types::errors::ContractError;
use common_types::reserved_addresses;

use super::contract::Contract;
use crate::rs_contracts::storage::db_contracts::ContractsDB;
use crate::rs_contracts::storage::db_trait::DataBase;
use crate::rs_contracts::storage::db_trait::DataCategory;

use crate::contracts::tools::method as method_tools;
use cita_trie::DB;
use cita_vm::state::State;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use tiny_keccak::keccak256;

use crate::cita_executive::{
    build_evm_context, build_vm_exec_params, call as vm_call, ExecutiveParams,
};
use crate::cita_vm_helper::get_interpreter_conf;
use crate::data_provider::Store as VMSubState;
use crate::libexecutor::block::EVMBlockDataProvider;

const AUTO_EXEC: &[u8] = &*b"autoExec()";
pub const AUTO_EXEC_QL_VALUE: u64 = 1_048_576;

lazy_static! {
    static ref AUTO_EXEC_ADDR: H160 = H160::from_str(reserved_addresses::AUTO_EXEC).unwrap();
    static ref AUTO_EXEC_HASH: Vec<u8> = method_tools::encode_to_vec(AUTO_EXEC);
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AutoContract {
    contracts: BTreeMap<u64, Option<String>>,
}

impl Default for AutoContract {
    fn default() -> Self {
        AutoContract {
            contracts: BTreeMap::new(),
        }
    }
}

impl AutoContract {
    pub fn init(str: String, contracts_db: Arc<ContractsDB>) {
        let mut a = AutoContract::default();
        a.contracts.insert(0, Some(str));
        let s = serde_json::to_string(&a).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"auto-contract".to_vec(),
            s.as_bytes().to_vec(),
        );
    }

    pub fn get_latest_item(
        &self,
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<AutoContract>, Option<AutoExec>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"auto-contract".to_vec())
            .expect("get store error")
        {
            let contract_map: AutoContract = serde_json::from_slice(&store).unwrap();
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

            let latest_item: AutoExec = serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            trace!("Contract latest item {:?}", latest_item);
            return (Some(contract_map), Some(latest_item));
        }
        (None, None)
    }
}

impl<B: DB + 'static> Contract<B> for AutoContract {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - auto exec - enter execute");
        let (contract_map, latest_item) =
            self.get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_item) {
            (Some(mut contract_map), Some(mut latest_item)) => {
                trace!(
                    "System contracts - auto exec - params input {:?}",
                    params.input
                );
                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        0x4420e486 => latest_item.register(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        0x844cbc43 => {
                            latest_item.auto_exec(&context, state.clone(), contracts_db.clone())
                        }
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
                        b"auto-contract".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );
                }
                return result;
            }
            _ => Err(ContractError::Internal("params error".to_owned())),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutoExec {
    contract_address: Address,
}

impl Default for AutoExec {
    fn default() -> Self {
        AutoExec {
            contract_address: Address::new(),
        }
    }
}

impl AutoExec {
    pub fn register(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - auto exec - register");
        let param_address = Address::from_slice(&params.input[16..36]);
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin")
            && param_address != self.contract_address
        {
            self.contract_address = param_address;
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

    pub fn auto_exec<B: DB + 'static>(
        &self,
        context: &Context,
        state: Arc<RefCell<State<B>>>,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - auto exec - auto_exec");
        let hash = &*AUTO_EXEC_HASH;
        let params = ExecutiveParams {
            code_address: Some(self.contract_address),
            sender: Address::from(0x0),
            to_address: Some(self.contract_address),
            gas: U256::from(AUTO_EXEC_QL_VALUE),
            gas_price: U256::from(1),
            value: U256::from(0),
            nonce: U256::from(0),
            data: Some(hash.to_vec()),
        };
        let block_provider = EVMBlockDataProvider::new(context.clone());
        let vm_exec_params = build_vm_exec_params(&params, state.clone());
        let mut sub_state = VMSubState::default();

        sub_state.evm_context = build_evm_context(&context.clone());
        sub_state.evm_cfg = get_interpreter_conf();
        let sub_state = Arc::new(RefCell::new(sub_state));

        match vm_call(
            Arc::new(block_provider),
            state.clone(),
            sub_state.clone(),
            contracts_db.clone(),
            &vm_exec_params.into(),
        ) {
            Ok(res) => Ok(res),
            Err(_e) => Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            )),
        }
    }
}

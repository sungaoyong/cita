use crate::rs_contracts::contracts::tool::check;
use crate::rs_contracts::contracts::tool::{extract_to_u32, get_latest_key};

use cita_types::{H256, U256};
use cita_vm::evm::{InterpreterParams, InterpreterResult, Log};
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
    static ref SET_PRICE: u32 = method::encode_to_u32(b"setQuotaPrice(uint256)");
    static ref GET_PRICE: u32 = method::encode_to_u32(b"getQuotaPrice()");
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PriceStore {
    pub contracts: BTreeMap<u64, Option<String>>,
}

impl PriceStore {
    pub fn init(str: String, contracts_db: Arc<ContractsDB>) -> Self {
        let mut a = PriceStore::default();
        a.contracts.insert(0, Some(str));
        let s = serde_json::to_string(&a).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"price".to_vec(),
            s.as_bytes().to_vec(),
        );
        a
    }

    pub fn get_latest_item(
        &self,
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<PriceStore>, Option<Price>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"price".to_vec())
            .expect("get store error")
        {
            let contract_map: PriceStore = serde_json::from_slice(&store).unwrap();
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
                .expect("get contract according to height error");
            let latest_price: Price = serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            trace!("Contract latest item {:?}", latest_price);

            return (Some(contract_map), Some(latest_price));
        }
        (None, None)
    }
}

impl<B: DB> Contract<B> for PriceStore {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Price contract - enter execute");
        let (contract_map, latest_price) =
            self.get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_price) {
            (Some(mut contract_map), Some(mut latest_price)) => {
                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        sig if sig == *GET_PRICE => latest_price.get_quota_price(),
                        sig if sig == *SET_PRICE => latest_price.set_quota_price(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        _ => panic!("Invalid function signature".to_owned()),
                    });

                if result.is_ok() & updated {
                    let new_price = latest_price;
                    let str = serde_json::to_string(&new_price).unwrap();
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
                        b"price".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );
                }
                return result;
            }
            _ => Err(ContractError::Internal("params error".to_owned())),
        }
    }

    fn create(&self) -> Box<dyn Contract<B>> {
        Box::new(PriceStore::default())
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Price {
    quota_price: U256,
}

impl Price {
    pub fn new(quota_price: U256) -> Self {
        Price { quota_price }
    }

    pub fn set_quota_price(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Price contract: set_quota_price");
        let param_quota_price = U256::from(&params.input[16..36]);
        // Note: Only admin can change quota price
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin")
            && param_quota_price > U256::zero()
        {
            self.quota_price = param_quota_price;
            *changed = true;

            let mut logs = Vec::new();
            let mut topics = Vec::new();
            let signature = "SetQuotaPrice(uint256)".as_bytes();
            topics.push(H256::from(keccak256(signature)));
            topics.push(H256::from(self.quota_price));
            topics.push(H256::default());
            topics.push(H256::default());
            let log = Log(params.contract.code_address, topics, vec![]);
            logs.push(log);

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

    pub fn get_quota_price(&self) -> Result<InterpreterResult, ContractError> {
        trace!("Price contract: get_quota_price");
        return Ok(InterpreterResult::Normal(
            H256::from(self.quota_price).to_vec(),
            0,
            vec![],
        ));
    }
}

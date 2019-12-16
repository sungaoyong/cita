use crate::rs_contracts::contracts::tool::check;
use crate::rs_contracts::contracts::tool::{extract_to_u32, get_latest_key};

use cita_types::{Address, H256, U256};
use cita_vm::evm::{InterpreterParams, InterpreterResult};
use common_types::context::Context;
use common_types::errors::ContractError;

use crate::rs_contracts::contracts::Contract;
use crate::rs_contracts::storage::db_contracts::ContractsDB;
use crate::rs_contracts::storage::db_trait::DataBase;
use crate::rs_contracts::storage::db_trait::DataCategory;

use cita_trie::DB;
use cita_vm::state::State;
use ethabi::Token;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use tiny_keccak::keccak256;

use crate::contracts::tools::method;
lazy_static! {
    static ref SET_STAKE: u32 = method::encode_to_u32(b"setStake(address,uint64)");
    static ref APPROVE_NODE: u32 = method::encode_to_u32(b"approveNode(address)");
    static ref DELETE_NODE: u32 = method::encode_to_u32(b"deleteNode(address)");
    static ref LIST_NODE: u32 = method::encode_to_u32(b"listNode()");
    static ref LIST_STAKE: u32 = method::encode_to_u32(b"listStake()");
    static ref GET_STATUS: u32 = method::encode_to_u32(b"getStatus(address)");
    static ref STAKE_PERMILLAGE: u32 = method::encode_to_u32(b"stakePermillage(address)");
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct NodeStore {
    pub contracts: BTreeMap<u64, Option<String>>,
}

impl NodeStore {
    pub fn init(str: String, contracts_db: Arc<ContractsDB>) -> Self {
        let mut a = NodeStore::default();
        a.contracts.insert(0, Some(str));
        let s = serde_json::to_string(&a).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"nodes".to_vec(),
            s.as_bytes().to_vec(),
        );
        a
    }

    pub fn get_latest_item(
        &self,
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<NodeStore>, Option<NodeManager>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"nodes".to_vec())
            .expect("get store error")
        {
            let contract_map: NodeStore = serde_json::from_slice(&store).unwrap();
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
            let latest_item: NodeManager = serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            trace!("Contract latest item {:?}", latest_item);

            return (Some(contract_map), Some(latest_item));
        }
        (None, None)
    }
}

impl<B: DB> Contract<B> for NodeStore {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - nodes - enter execute");
        let (contract_map, latest_item) =
            self.get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_item) {
            (Some(mut contract_map), Some(mut latest_item)) => {
                trace!("System contracts - nodes - params input {:?}", params.input);
                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        sig if sig == *SET_STAKE => latest_item.set_stake(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *APPROVE_NODE => latest_item.approve_node(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *DELETE_NODE => latest_item.delete_node(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *LIST_NODE => latest_item.list_nodes(params),
                        sig if sig == *LIST_STAKE => latest_item.list_stake(params),
                        sig if sig == *GET_STATUS => latest_item.get_status(params),
                        sig if sig == *STAKE_PERMILLAGE => latest_item.stake_permillage(params),
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
                        b"nodes".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );
                }
                return result;
            }
            _ => Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            )),
        }
    }

    fn create(&self) -> Box<dyn Contract<B>> {
        Box::new(NodeStore::default())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeManager {
    status: BTreeMap<Address, bool>, // false -> closed, false -> open
    nodes: Vec<Address>,
    stakes: BTreeMap<Address, U256>,
}

impl NodeManager {
    pub fn new(nodes: Vec<Address>, stakes: Vec<U256>) -> Self {
        let mut stakes_map = BTreeMap::new();
        let mut status_map = BTreeMap::new();
        for i in 0..nodes.len() {
            stakes_map.insert(nodes[i], stakes[i]);
            status_map.insert(nodes[i], true);
        }
        NodeManager {
            status: status_map,
            nodes: nodes,
            stakes: stakes_map,
        }
    }

    pub fn set_stake(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Node contract: set_stake");
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin") {
            let param_address = Address::from_slice(&params.input[16..36]);
            let param_stake = U256::from(&params.input[36..]);
            trace!("param address decoded is {:?}", param_address);
            trace!("param stake decoded is {:?}", param_stake);
            if let Some(stake) = self.stakes.get_mut(&param_address) {
                *stake = param_stake;
                *changed = true;

                return Ok(InterpreterResult::Normal(
                    H256::from(1).0.to_vec(),
                    params.gas_limit,
                    vec![],
                ));
            }
        }
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn approve_node(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Node contract: approve_node");
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin") {
            let param_address = Address::from_slice(&params.input[16..36]);
            if !*self.status.get(&param_address).unwrap_or(&false) {
                self.status.insert(param_address, true);
                self.stakes.insert(param_address, U256::from(0));
                self.nodes.push(param_address);
                *changed = true;

                return Ok(InterpreterResult::Normal(
                    H256::from(1).0.to_vec(),
                    params.gas_limit,
                    vec![],
                ));
            }
        }
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn delete_node(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Node contract: delete_node");
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin") {
            let param_address = Address::from_slice(&params.input[16..36]);
            if *self.status.get(&param_address).unwrap_or(&false) {
                self.nodes.retain(|&n| n != param_address);
                self.stakes.remove(&param_address);
                if let Some(s) = self.status.get_mut(&param_address) {
                    *s = false;
                }
                if let Some(s) = self.stakes.get_mut(&param_address) {
                    *s = U256::zero();
                }
                *changed = true;
                return Ok(InterpreterResult::Normal(
                    H256::from(1).0.to_vec(),
                    params.gas_limit,
                    vec![],
                ));
            }
        }
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn list_nodes(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Node contract: list_nodes");
        let nodes = self
            .nodes
            .iter()
            .map(|i| Token::Address(i.0))
            .collect::<Vec<ethabi::Token>>();
        trace!("list nodes is {:?}", nodes);
        let mut tokens = Vec::new();
        tokens.push(ethabi::Token::Array(nodes));
        return Ok(InterpreterResult::Normal(
            ethabi::encode(&tokens),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn list_stake(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Node contract: list_stake");
        let mut tokens = Vec::new();
        let mut stakes = Vec::new();
        for (_key, value) in self.stakes.iter() {
            stakes.push(Token::Uint(H256::from(value).0));
        }
        trace!("list stakes is {:?}", stakes);
        tokens.push(ethabi::Token::Array(stakes));
        return Ok(InterpreterResult::Normal(
            ethabi::encode(&tokens),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn get_status(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Node contract: get_status");
        let param_address = Address::from_slice(&params.input[16..36]);
        if *self.status.get(&param_address).unwrap_or(&false) {
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

    pub fn stake_permillage(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        // Todo only in charge mode
        trace!("Node contract: stake_permillage");
        let param_address = Address::from_slice(&params.input[16..36]);
        let node_stakes = self.stakes.get(&param_address).unwrap();

        let total = U256::zero();
        for i in self.stakes.values() {
            total.overflowing_add(*i);
        }

        if total == U256::zero() {
            return Ok(InterpreterResult::Normal(
                H256::from(0).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        } else {
            let extend_stake = node_stakes.overflowing_mul(U256::from(1000)).0;
            let res = extend_stake.checked_div(total).unwrap();
            return Ok(InterpreterResult::Normal(
                H256::from(res).to_vec(),
                params.gas_limit,
                vec![],
            ));
        }
    }
}

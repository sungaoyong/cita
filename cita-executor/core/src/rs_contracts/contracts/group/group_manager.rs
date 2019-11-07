use crate::rs_contracts::contracts::utils::{clean_0x, extract_to_u32, get_latest_key};

use cita_types::traits::LowerHex;
use cita_types::{Address, H256, U256};
use cita_vm::evm::{InterpreterParams, InterpreterResult, Log};
use common_types::context::Context;
use common_types::errors::ContractError;

use crate::rs_contracts::contracts::group::Group;
use crate::rs_contracts::contracts::Contract;
use crate::rs_contracts::storage::db_contracts::ContractsDB;
use crate::rs_contracts::storage::db_trait::DataBase;
use crate::rs_contracts::storage::db_trait::DataCategory;

use cita_trie::DB;
use cita_vm::state::State;
use ethabi::param_type::ParamType;
use ethabi::Token;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use tiny_keccak::keccak256;

use crate::cita_executive::create_address_from_address_and_nonce;
use cita_vm::state::StateObjectInfo;
use common_types::reserved_addresses;
use ethabi::token::LenientTokenizer;
use ethabi::token::Tokenizer;

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupStore {
    // key -> height, value -> json(GroupManager)
    contracts: BTreeMap<u64, Option<String>>,
}

impl Default for GroupStore {
    fn default() -> GroupStore {
        GroupStore {
            contracts: BTreeMap::new(),
        }
    }
}

impl GroupStore {
    pub fn init(str: String, contracts_db: Arc<ContractsDB>) {
        let mut a = GroupStore::default();

        a.contracts.insert(0, Some(str));
        let s = serde_json::to_string(&a).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"group-contract".to_vec(),
            s.as_bytes().to_vec(),
        );
    }

    pub fn get_latest_item(
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<GroupStore>, Option<GroupManager>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"group-contract".to_vec())
            .expect("get store error")
        {
            let contract_map: GroupStore = serde_json::from_slice(&store).unwrap();
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
            let latest_item: GroupManager = serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            trace!("Contract latest item {:?}", latest_item);

            return (Some(contract_map), Some(latest_item));
        }
        (None, None)
    }

    pub fn get_account_groups(
        account: Address,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Option<Vec<Address>> {
        let mut groups = Vec::new();
        match GroupStore::get_latest_item(context.block_number, contracts_db.clone()) {
            (_, Some(latest_group_manager)) => {
                for (addr, entry) in latest_group_manager.groups.iter() {
                    if entry.in_group(account) {
                        groups.push(*addr);
                    }
                }
                return Some(groups);
            }
            _ => None,
        }
    }
}

impl<B: DB> Contract<B> for GroupStore {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - group - enter execute");
        let (contract_map, latest_group_manager) =
            GroupStore::get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_group_manager) {
            (Some(mut contract_map), Some(mut latest_group_manager)) => {
                trace!("System contracts - group - params input {:?}", params.input);
                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        0xd7cd7209 => latest_group_manager.new_group(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                            state.clone(),
                        ),
                        0xbaeb8cad => latest_group_manager.delete_group(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        0x7eafcdb1 => latest_group_manager.update_group_name(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        0x2c84e31f => latest_group_manager.add_accounts(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        0xd86df333 => latest_group_manager.delete_accounts(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        0xeadf4672 => latest_group_manager.check_scope(params),
                        0x7321cc97 => latest_group_manager.query_groups(params),
                        0xdff7eafe => latest_group_manager.query_name(params),
                        0x223964bc => latest_group_manager.query_accounts(params),
                        0x5bbfb698 => latest_group_manager.query_childs(params),
                        0xa881ff41 => latest_group_manager.query_childs_len(params),
                        0xce8b7d7f => latest_group_manager.query_parent(params),
                        0x1b151dd7 => latest_group_manager.in_group(params),
                        _ => panic!("Invalid function signature {} ", signature),
                    });

                if result.is_ok() & updated {
                    let new_item = latest_group_manager;
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
                        b"group-contract".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );

                    // debug information, can be ommited
                    // let bin_map = contracts_db
                    //     .get(DataCategory::Contracts, b"group-contract".to_vec())
                    //     .unwrap();
                    // let str = String::from_utf8(bin_map.unwrap()).unwrap();
                    // let contracts: GroupStore = serde_json::from_str(&str).unwrap();
                    // trace!("System contract group {:?} after update.", contracts);
                }
                return result;
            }
            _ => Err(ContractError::Internal("params error".to_owned())),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct GroupManager {
    pub groups: BTreeMap<Address, Group>,
}

impl GroupManager {
    pub fn new(name: &str, parent: Address, accounts: Vec<Address>) -> Self {
        let mut group_manager = GroupManager::default();
        let root_group = Group::new(name.to_string(), parent, accounts);
        group_manager
            .groups
            .insert(Address::from(reserved_addresses::GROUP), root_group);
        group_manager
    }

    pub fn new_group<B: DB>(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - group - new group, input {:?}",
            params.input
        );

        let tokens = vec![
            ParamType::Address,
            ParamType::FixedBytes(32),
            ParamType::Array(Box::new(ParamType::Address)),
        ];

        if let Ok(args) = ethabi::decode(&tokens, &params.input[4..]) {
            match (&args[0], &args[1], &args[2]) {
                (Token::Address(origin), Token::FixedBytes(name), Token::Array(addrs)) => {
                    let name = H256::from_slice(name);
                    let origin = Address::from_slice(origin);
                    let accounts = addrs
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();

                    trace!("origin in newGroup is {:?}", origin);
                    trace!("name newGroup is {:?}", name);
                    trace!("accounts in newGroup is {:?}", accounts);

                    let group = Group::new(name.lower_hex(), origin, accounts);
                    let nonce = state
                        .borrow_mut()
                        .nonce(&Address::from(reserved_addresses::GROUP_CREATOR))
                        .unwrap();
                    let group_address = create_address_from_address_and_nonce(
                        &Address::from(reserved_addresses::GROUP_CREATOR),
                        &nonce,
                    );

                    // increase nonce
                    state
                        .borrow_mut()
                        .inc_nonce(&Address::from(reserved_addresses::GROUP_CREATOR))
                        .unwrap();

                    // add child
                    if let Some(origin_group) = self.groups.get_mut(&origin) {
                        origin_group.add_child(group_address);
                    }
                    self.groups.insert(group_address, group);

                    let mut logs = Vec::new();
                    let mut topics = Vec::new();
                    let signature = "newGroup(address,bytes32,address[])".as_bytes();
                    topics.push(H256::from(keccak256(signature)));
                    topics.push(H256::from(group_address));
                    let log = Log(group_address, topics, vec![]);
                    logs.push(log);

                    *changed = true;
                    return Ok(InterpreterResult::Normal(
                        H256::from(0).0.to_vec(),
                        params.gas_limit,
                        logs,
                    ));
                }
                _ => unreachable!(),
            }
        }

        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn delete_group(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - group - delete_group, input {:?}",
            params.input
        );

        let origin_address = Address::from(&params.input[16..36]);
        let target_address = Address::from(&params.input[48..68]);
        if self.check_scope_interval(origin_address, target_address) {
            if let Some(origin_group) = self.groups.get_mut(&origin_address) {
                origin_group.delete_child(target_address);
                self.groups.remove(&target_address);
                *changed = true;
                return Ok(InterpreterResult::Normal(
                    H256::from(0).0.to_vec(),
                    params.gas_limit,
                    vec![],
                ));
            }
        }

        return Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ));
    }

    pub fn update_group_name(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - group - update_group_name, input {:?}",
            params.input
        );
        // todo check these params
        let origin_address = Address::from(&params.input[16..36]);
        let target_address = Address::from(&params.input[48..68]);
        let name = H256::from(&params.input[68..100]).lower_hex();
        trace!("origin address {:?}", origin_address);
        trace!("target address {:?}", target_address);
        trace!("name {:?}", name);

        if self.check_scope_interval(origin_address, target_address) {
            if let Some(group) = self.groups.get_mut(&target_address) {
                group.update_name(&name);
                *changed = true;
                return Ok(InterpreterResult::Normal(
                    H256::from(1).0.to_vec(),
                    params.gas_limit,
                    vec![],
                ));
            }
        }

        return Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ));
    }

    pub fn add_accounts(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - group - add_accounts, input {:?}",
            params.input
        );

        // decode params
        let tokens = vec![
            ParamType::Address,
            ParamType::Address,
            ParamType::Array(Box::new(ParamType::Address)),
        ];
        if let Ok(args) = ethabi::decode(&tokens, &params.input[4..]) {
            match (&args[0], &args[1], &args[2]) {
                (Token::Address(origin), Token::Address(target), Token::Array(accounts)) => {
                    let origin_address = Address::from_slice(origin);
                    let target_address = Address::from_slice(target);
                    let accounts_address = accounts
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();
                    trace!("origin address: {:?}", origin_address);
                    trace!("target address: {:?}", target_address);
                    trace!("account addresses: {:?}", accounts_address);

                    if self.check_scope_interval(origin_address, target_address) {
                        if let Some(group) = self.groups.get_mut(&target_address) {
                            group.add_accounts(accounts_address);

                            *changed = true;
                            return Ok(InterpreterResult::Normal(
                                H256::from(1).0.to_vec(),
                                params.gas_limit,
                                vec![],
                            ));
                        }
                    }
                }
                _ => return Err(ContractError::Internal("error params".to_owned())),
            }
        }
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn delete_accounts(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - group - delete_accounts, input {:?}",
            params.input
        );

        let tokens = vec![
            ParamType::Address,
            ParamType::Address,
            ParamType::Array(Box::new(ParamType::Address)),
        ];

        if let Ok(args) = ethabi::decode(&tokens, &params.input[4..]) {
            match (&args[0], &args[1], &args[2]) {
                (Token::Address(origin), Token::Address(target), Token::Array(accounts)) => {
                    let origin_address = Address::from_slice(origin);
                    let target_address = Address::from_slice(target);
                    let accounts_address = accounts
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();
                    trace!("origin address: {:?}", origin_address);
                    trace!("target address: {:?}", target_address);
                    trace!("account addresses: {:?}", accounts_address);

                    if self.check_scope_interval(origin_address, target_address) {
                        if let Some(group) = self.groups.get_mut(&target_address) {
                            group.delete_accounts(accounts_address);

                            *changed = true;
                            return Ok(InterpreterResult::Normal(
                                H256::from(1).0.to_vec(),
                                params.gas_limit,
                                vec![],
                            ));
                        }
                    }
                }
                _ => return Err(ContractError::Internal("error params".to_owned())),
            }
        }
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn query_groups(
        &mut self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - group - query_groups, input {:?}",
            params.input
        );

        let mut returned_groups = Vec::new();
        for g in self.groups.keys() {
            returned_groups.push(Token::Address(g.0));
        }
        let mut tokens = Vec::new();
        tokens.push(Token::Array(returned_groups));

        return Ok(InterpreterResult::Normal(
            ethabi::encode(&tokens),
            params.gas_limit,
            vec![],
        ));
    }

    // The follow interface to Group
    pub fn query_name(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - group  - query_name");
        let group_address = Address::from(&params.input[16..36]);
        trace!("group address in query_name: {}", group_address.lower_hex());
        if let Some(group) = self.groups.get(&group_address) {
            let name = group.query_name();
            trace!("group name {:?}", name);
            let res =
                LenientTokenizer::tokenize(&ParamType::FixedBytes(32), &clean_0x(&name)).unwrap();
            trace!("group name bin {:?}", res);
            return Ok(InterpreterResult::Normal(
                res.clone().to_fixed_bytes().unwrap(),
                params.gas_limit,
                vec![],
            ));
        }

        return Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn query_accounts(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - group  - query_accounts");
        let group_address = Address::from(&params.input[16..36]);

        trace!("group address in query_name: {}", group_address.lower_hex());
        if let Some(group) = self.groups.get(&group_address) {
            let accounts = group.query_accounts();

            let mut returned_accounts = Vec::new();
            for a in accounts.iter() {
                returned_accounts.push(Token::Address(a.0));
            }
            let mut tokens = Vec::new();
            tokens.push(Token::Array(returned_accounts));
            return Ok(InterpreterResult::Normal(
                ethabi::encode(&tokens),
                params.gas_limit,
                vec![],
            ));
        }

        return Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn query_childs(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - group  - query_childs");
        let group_address = Address::from(&params.input[16..36]);
        trace!("group address in query_name: {}", group_address.lower_hex());
        if let Some(group) = self.groups.get(&group_address) {
            let childs = group.query_childs();

            let mut returned_childs = Vec::new();
            for c in childs.iter() {
                returned_childs.push(Token::Address(c.0));
            }
            let mut tokens = Vec::new();
            tokens.push(Token::Array(returned_childs));
            return Ok(InterpreterResult::Normal(
                ethabi::encode(&tokens),
                params.gas_limit,
                vec![],
            ));
        }

        return Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn query_childs_len(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - group  - queryChildLength");
        let group_address = Address::from(&params.input[16..36]);
        trace!("group address in query_name: {}", group_address.lower_hex());
        if let Some(group) = self.groups.get(&group_address) {
            let len = group.query_childs().len();

            return Ok(InterpreterResult::Normal(
                H256::from(U256::from(len)).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        return Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn query_parent(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - group  - queryParent");
        let group_address = Address::from(&params.input[16..36]);
        trace!("group address in query_name: {}", group_address.lower_hex());
        if let Some(group) = self.groups.get(&group_address) {
            let parent = group.query_parent();

            return Ok(InterpreterResult::Normal(
                H256::from(parent).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        return Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn in_group(&self, params: &InterpreterParams) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - group  - inGroup");

        let group_address = Address::from(&params.input[16..36]);
        let account_address = Address::from(&params.input[48..68]);
        trace!("group address = {}", group_address.lower_hex());
        trace!("account address = {}", account_address.lower_hex());

        if let Some(group) = self.groups.get(&group_address) {
            if group.in_group(account_address) {
                return Ok(InterpreterResult::Normal(
                    H256::from(1).0.to_vec(),
                    params.gas_limit,
                    vec![],
                ));
            }
        }

        return Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn check_scope(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - group  - inGroup");

        let origin_address = Address::from(&params.input[16..36]);
        let target_address = Address::from(&params.input[48..68]);
        trace!("origin address = {}", origin_address.lower_hex());
        trace!("target address = {}", target_address.lower_hex());

        if self.check_scope_interval(origin_address, target_address) {
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        return Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn check_scope_interval(&self, origin: Address, target: Address) -> bool {
        let mut parent = target;
        while parent != Address::from("0x0000000000000000000000000000000000000000") {
            if origin == parent {
                return true;
            }
            if let Some(group) = self.groups.get(&parent) {
                parent = group.query_parent();
            } else {
                return false;
            }
        }
        false
    }
}

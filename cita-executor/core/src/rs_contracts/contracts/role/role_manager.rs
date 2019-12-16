use crate::rs_contracts::contracts::tool::utils::{clean_0x, extract_to_u32, get_latest_key};

use cita_types::traits::LowerHex;
use cita_types::{Address, H256, U256};
use cita_vm::evm::{InterpreterParams, InterpreterResult, Log};
use common_types::context::Context;
use common_types::errors::ContractError;

use crate::rs_contracts::contracts::role::role::Role;
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

use crate::contracts::tools::method;

lazy_static! {
    static ref NEW_ROLE: u32 = method::encode_to_u32(b"newRole(bytes32,address[])");
    static ref DEL_ROLE: u32 = method::encode_to_u32(b"deleteRole(address)");
    static ref UPDATE_ROLE_NAME: u32 = method::encode_to_u32(b"updateRoleName(address,bytes32)");
    static ref ADD_PERMISSION: u32 = method::encode_to_u32(b"addPermissions(address,address[])");
    static ref DEL_PERMISSION: u32 = method::encode_to_u32(b"deletePermissions(address,address[])");
    static ref SET_ROLE: u32 = method::encode_to_u32(b"setRole(address,address)");
    static ref CANCEL_ROLE: u32 = method::encode_to_u32(b"cancelRole(address,address)");
    static ref CLEAR_ROLE: u32 = method::encode_to_u32(b"clearRole(address)");
    static ref QUERY_ROLES: u32 = method::encode_to_u32(b"queryRoles(address)");
    static ref QUERY_ACCOUNTS: u32 = method::encode_to_u32(b"queryAccounts(address)");
    static ref QUERY_ROLE: u32 = method::encode_to_u32(b"queryRole(address)");
    static ref QUERY_NAME: u32 = method::encode_to_u32(b"queryName(address)");
    static ref QUERY_PERMISSIONS: u32 = method::encode_to_u32(b"queryPermissions(address)");
    static ref PERMISSIONS_LEN: u32 = method::encode_to_u32(b"lengthOfPermissions(address)");
    static ref IN_PERMISSIONS: u32 = method::encode_to_u32(b"inPermissions(address,address)");
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct RoleStore {
    // key -> height, value -> json(RoleManager)
    pub contracts: BTreeMap<u64, Option<String>>,
}

impl RoleStore {
    pub fn init(str: String, contracts_db: Arc<ContractsDB>) -> Self {
        let mut a = RoleStore::default();

        a.contracts.insert(0, Some(str));
        let s = serde_json::to_string(&a).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"role".to_vec(),
            s.as_bytes().to_vec(),
        );
        a
    }

    pub fn get_latest_item(
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<RoleStore>, Option<RoleManager>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"role".to_vec())
            .expect("get store error")
        {
            let contract_map: RoleStore = serde_json::from_slice(&store).unwrap();
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
            let latest_item: RoleManager = serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            trace!("Contract latest item {:?}", latest_item);

            return (Some(contract_map), Some(latest_item));
        }
        (None, None)
    }
}

impl<B: DB> Contract<B> for RoleStore {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - role - enter execute");
        let (contract_map, latest_manager) =
            RoleStore::get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_manager) {
            (Some(mut contract_map), Some(mut latest_manager)) => {
                trace!("System contracts - role - params input {:?}", params.input);
                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        sig if sig == *NEW_ROLE => latest_manager.new_role(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                            state.clone(),
                        ),
                        sig if sig == *DEL_ROLE => latest_manager.delete_role(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *UPDATE_ROLE_NAME => latest_manager.update_role_name(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *ADD_PERMISSION => latest_manager.add_permissions(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *DEL_PERMISSION => latest_manager.delete_permissions(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *SET_ROLE => latest_manager.set_role(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *CANCEL_ROLE => latest_manager.cancel_role(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *CLEAR_ROLE => latest_manager.clear_role(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *QUERY_ROLES => latest_manager.query_roles(params),
                        sig if sig == *QUERY_ACCOUNTS => latest_manager.query_accounts(params),
                        sig if sig == *QUERY_ROLE => latest_manager.query_role(params),
                        sig if sig == *QUERY_NAME => latest_manager.query_name(params),
                        sig if sig == *QUERY_PERMISSIONS => latest_manager.query_permssions(params),
                        sig if sig == *PERMISSIONS_LEN => {
                            latest_manager.query_permssions_length(params)
                        }
                        sig if sig == *IN_PERMISSIONS => latest_manager.in_permission(params),
                        _ => panic!("Invalid function signature {} ", signature),
                    });

                if result.is_ok() & updated {
                    let new_item = latest_manager;
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
                        b"role".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );
                }
                return result;
            }
            _ => Err(ContractError::Internal("params error".to_owned())),
        }
    }

    fn create(&self) -> Box<dyn Contract<B>> {
        Box::new(RoleStore::default())
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct RoleManager {
    pub roles: BTreeMap<Address, Role>,
}

impl RoleManager {
    pub fn new_role<B: DB>(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - new role, input {:?}",
            params.input
        );

        let tokens = vec![
            ParamType::FixedBytes(32),
            ParamType::Array(Box::new(ParamType::Address)),
        ];

        if let Ok(args) = ethabi::decode(&tokens, &params.input[4..]) {
            match (&args[0], &args[1]) {
                (Token::FixedBytes(name), Token::Array(addrs)) => {
                    let name = H256::from_slice(name);
                    let permissions = addrs
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();

                    trace!("name in newRole is {:?}", name);
                    trace!("permissions in newRole is {:?}", permissions);

                    let role = Role::new(name.lower_hex(), permissions);
                    let nonce = state
                        .borrow_mut()
                        .nonce(&Address::from(reserved_addresses::ROLE_CREATOR))
                        .unwrap();
                    let role_address = create_address_from_address_and_nonce(
                        &Address::from(reserved_addresses::ROLE_CREATOR),
                        &nonce,
                    );

                    // increase nonce
                    state
                        .borrow_mut()
                        .inc_nonce(&Address::from(reserved_addresses::ROLE_CREATOR))
                        .unwrap();

                    self.roles.insert(role_address, role);

                    let mut logs = Vec::new();
                    let mut topics = Vec::new();
                    let signature = "newRole(bytes32,address[])".as_bytes();
                    topics.push(H256::from(keccak256(signature)));
                    topics.push(H256::from(role_address));
                    let log = Log(role_address, topics, vec![]);
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

    pub fn delete_role(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - delete_role, input {:?}",
            params.input
        );
        let param_address = Address::from(&params.input[16..36]);
        self.roles.remove(&param_address);

        *changed = true;
        Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ))
    }

    pub fn update_role_name(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - update role name, input {:?}",
            params.input
        );
        let role_address = Address::from(&params.input[16..36]);
        let name = H256::from(&params.input[36..68]).lower_hex();
        trace!("role address {:?}", role_address);
        trace!("name {:?}", name);

        if let Some(role) = self.roles.get_mut(&role_address) {
            role.update_name(&name);

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

    pub fn add_permissions(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - add permissions, input {:?}",
            params.input
        );
        let tokens = vec![
            ParamType::Address,
            ParamType::Array(Box::new(ParamType::Address)),
        ];

        if let Ok(args) = ethabi::decode(&tokens, &params.input[4..]) {
            match (&args[0], &args[1]) {
                (Token::Address(role), Token::Array(addrs)) => {
                    let role_address = Address::from_slice(role);
                    let permissions = addrs
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();

                    trace!("role address: {:?}", role_address);
                    trace!("permissions addresses: {:?}", permissions);

                    if let Some(role) = self.roles.get_mut(&role_address) {
                        role.add_permissions(permissions);

                        *changed = true;
                        return Ok(InterpreterResult::Normal(
                            H256::from(1).0.to_vec(),
                            params.gas_limit,
                            vec![],
                        ));
                    }
                }
                _ => return Err(ContractError::Internal("error params".to_owned())),
            }
        }

        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn delete_permissions(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - delete permissions, input {:?}",
            params.input
        );

        let tokens = vec![
            ParamType::Address,
            ParamType::Array(Box::new(ParamType::Address)),
        ];

        if let Ok(args) = ethabi::decode(&tokens, &params.input[4..]) {
            match (&args[0], &args[1]) {
                (Token::Address(role), Token::Array(addrs)) => {
                    let role_address = Address::from_slice(role);
                    let permissions = addrs
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();

                    trace!("role address: {:?}", role_address);
                    trace!("permissions addresses: {:?}", permissions);

                    if let Some(role) = self.roles.get_mut(&role_address) {
                        role.delete_permissions(permissions);

                        *changed = true;
                        return Ok(InterpreterResult::Normal(
                            H256::from(1).0.to_vec(),
                            params.gas_limit,
                            vec![],
                        ));
                    }
                }
                _ => return Err(ContractError::Internal("error params".to_owned())),
            }
        }

        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn set_role(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - set role, input {:?}",
            params.input
        );
        let account_address = Address::from(&params.input[16..36]);
        let role_address = Address::from(&params.input[48..68]);

        if let Some(role) = self.roles.get_mut(&role_address) {
            role.add_account(account_address);

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

    pub fn cancel_role(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - cancel role, input {:?}",
            params.input
        );

        let account_address = Address::from(&params.input[16..36]);
        let role_address = Address::from(&params.input[48..68]);
        trace!("account address is {:?}", account_address);
        trace!("role address is {:?}", role_address);

        if let Some(role) = self.roles.get_mut(&role_address) {
            role.delete_account(account_address);

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

    pub fn clear_role(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        _context: &Context,
        _contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - clear role, input {:?}",
            params.input
        );

        let account_address = Address::from(&params.input[16..36]);
        trace!("account address is {:?}", account_address);
        for (_, role) in self.roles.iter_mut() {
            if role.in_accounts(&account_address) {
                role.delete_account(account_address);
                *changed = true;
            }
        }
        if *changed {
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

    pub fn query_roles(
        &mut self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - query_roles, input {:?}",
            params.input
        );

        let mut roles = Vec::new();
        for i in self.roles.keys() {
            roles.push(Token::Address(i.0));
        }
        let mut tokens = Vec::new();
        tokens.push(Token::Array(roles));

        return Ok(InterpreterResult::Normal(
            ethabi::encode(&tokens),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn query_accounts(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - query_accounts, input {:?}",
            params.input
        );

        let mut token_accounts = Vec::new();
        for (_, role) in self.roles.iter() {
            for i in role.query_accounts().iter() {
                // TODO: remove duplicated accounts
                token_accounts.push(Token::Address(i.0));
            }
        }
        let mut tokens = Vec::new();
        tokens.push(Token::Array(token_accounts));

        return Ok(InterpreterResult::Normal(
            ethabi::encode(&tokens),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn query_role(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - query_role, input {:?}",
            params.input
        );
        let role_address = Address::from(&params.input[16..36]);
        if let Some(role) = self.roles.get(&role_address) {
            let name = role.query_name();
            let permissions = role.query_permssions();

            let token_name =
                LenientTokenizer::tokenize(&ParamType::FixedBytes(32), &clean_0x(&name)).unwrap();
            let mut token_permissions = Vec::new();
            for a in permissions.iter() {
                token_permissions.push(Token::Address(a.0));
            }

            let mut tokens = Vec::new();
            tokens.push(token_name);
            tokens.push(Token::Array(token_permissions));

            return Ok(InterpreterResult::Normal(
                ethabi::encode(&tokens),
                params.gas_limit,
                vec![],
            ));
        }

        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn query_name(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - query_name, input {:?}",
            params.input
        );

        let role_address = Address::from(&params.input[16..36]);
        if let Some(role) = self.roles.get(&role_address) {
            let name = role.query_name();
            let res =
                LenientTokenizer::tokenize(&ParamType::FixedBytes(32), &clean_0x(&name)).unwrap();
            return Ok(InterpreterResult::Normal(
                res.clone().to_fixed_bytes().unwrap(),
                params.gas_limit,
                vec![],
            ));
        }

        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn query_permssions(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - query_permssions, input {:?}",
            params.input
        );

        let role_address = Address::from(&params.input[16..36]);
        if let Some(role) = self.roles.get(&role_address) {
            let permissions = role.query_permssions();
            let mut token_permissions = Vec::new();
            for a in permissions.iter() {
                token_permissions.push(Token::Address(a.0));
            }

            let mut tokens = Vec::new();
            tokens.push(Token::Array(token_permissions));

            return Ok(InterpreterResult::Normal(
                ethabi::encode(&tokens),
                params.gas_limit,
                vec![],
            ));
        }

        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn query_permssions_length(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - query_permssions_length, input {:?}",
            params.input
        );
        let role_address = Address::from(&params.input[16..36]);
        if let Some(role) = self.roles.get(&role_address) {
            let len = role.query_permssions_len();
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

    pub fn in_permission(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!(
            "System contract - role - in_permission, input {:?}",
            params.input
        );

        let role_address = Address::from(&params.input[16..36]);
        let permission_address = Address::from(&params.input[48..68]);
        trace!("role address = {}", role_address.lower_hex());
        trace!("permission address = {}", permission_address.lower_hex());

        if let Some(role) = self.roles.get(&role_address) {
            if role.in_permissions(permission_address) {
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
}

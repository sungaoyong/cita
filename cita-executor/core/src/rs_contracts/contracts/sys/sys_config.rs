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

use crate::rs_contracts::contracts::tool::utils::encode_string;
use cita_trie::DB;
use cita_vm::state::State;
use ethabi::param_type::ParamType;
use ethabi::Token;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use tiny_keccak::keccak256;

use crate::contracts::tools::method;
lazy_static! {
    static ref SET_OPERATOR: u32 = method::encode_to_u32(b"setOperator(string)");
    static ref SET_WEBSITE: u32 = method::encode_to_u32(b"setWebsite(string)");
    static ref SET_CHAIN_NAME: u32 = method::encode_to_u32(b"setChainName(string)");
    static ref SET_BLOCK_INTERVAL: u32 = method::encode_to_u32(b"setBlockInterval(uint64)");
    static ref GET_DELAY_BLOCK_NUMBER: u32 = method::encode_to_u32(b"getDelayBlockNumber()");
    static ref GET_PERM_CHECK: u32 = method::encode_to_u32(b"getPermissionCheck()");
    static ref GET_SEND_PERM_CHECK: u32 = method::encode_to_u32(b"getSendTxPermissionCheck()");
    static ref GET_CREATE_PERM_CHECK: u32 =
        method::encode_to_u32(b"getCreateContractPermissionCheck()");
    static ref GET_QUOTA_CHECK: u32 = method::encode_to_u32(b"getQuotaCheck()");
    static ref GET_FEE_BACH_CHECK: u32 = method::encode_to_u32(b"getFeeBackPlatformCheck()");
    static ref GET_CHAIN_OWNER: u32 = method::encode_to_u32(b"getChainOwner()");
    static ref GET_CHAIN_NAME: u32 = method::encode_to_u32(b"getChainName()");
    static ref GET_CHAIN_ID: u32 = method::encode_to_u32(b"getChainId()");
    static ref GET_CHAIN_ID_V1: u32 = method::encode_to_u32(b"getChainIdV1()");
    static ref GET_OPERATOR: u32 = method::encode_to_u32(b"getOperator()");
    static ref GET_WEBSITE: u32 = method::encode_to_u32(b"getWebsite()");
    static ref GET_BLOCK_INTERVAL: u32 = method::encode_to_u32(b"getBlockInterval()");
    static ref GET_ECONOMICAL_MODEL: u32 = method::encode_to_u32(b"getEconomicalModel()");
    static ref GET_TOKEN_INFO: u32 = method::encode_to_u32(b"getTokenInfo()");
    static ref GET_AUTO_EXEC: u32 = method::encode_to_u32(b"getAutoExec()");
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SystemStore {
    pub contracts: BTreeMap<u64, Option<String>>,
}

impl SystemStore {
    pub fn init(str: String, contracts_db: Arc<ContractsDB>) -> Self {
        let mut a = SystemStore::default();
        a.contracts.insert(0, Some(str.clone()));

        let s = serde_json::to_string(&a).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"sys".to_vec(),
            s.as_bytes().to_vec(),
        );
        a
    }

    pub fn get_latest_item(
        &self,
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<SystemStore>, Option<SysConfig>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"sys".to_vec())
            .expect("get store error")
        {
            let contract_map: SystemStore = serde_json::from_slice(&store).unwrap();
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
            let latest_item: SysConfig = serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            trace!("Contract latest item {:?}", latest_item);

            return (Some(contract_map), Some(latest_item));
        }

        (None, None)
    }
}

impl<B: DB> Contract<B> for SystemStore {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - system - enter execute");
        let (contract_map, latest_item) =
            self.get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_item) {
            (Some(mut contract_map), Some(mut latest_item)) => {
                trace!(
                    "System contracts - system - params input {:?}",
                    params.input
                );
                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        sig if sig == *SET_OPERATOR => latest_item.set_operator(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *SET_WEBSITE => latest_item.set_website(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *SET_CHAIN_NAME => latest_item.set_chain_name(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *SET_BLOCK_INTERVAL => latest_item.set_block_interval(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *GET_DELAY_BLOCK_NUMBER => {
                            latest_item.get_delay_block_number(params)
                        }
                        sig if sig == *GET_PERM_CHECK => latest_item.get_permission_check(params),
                        sig if sig == *GET_SEND_PERM_CHECK => {
                            latest_item.get_send_tx_permission_check(params)
                        }
                        sig if sig == *GET_CREATE_PERM_CHECK => {
                            latest_item.get_create_contract_permission_check(params)
                        }
                        sig if sig == *GET_QUOTA_CHECK => latest_item.get_quota_check(params),
                        sig if sig == *GET_FEE_BACH_CHECK => {
                            latest_item.get_fee_back_platform_check(params)
                        }
                        sig if sig == *GET_CHAIN_OWNER => latest_item.get_chain_owner(params),
                        sig if sig == *GET_CHAIN_NAME => latest_item.get_chain_name(params),
                        sig if sig == *GET_CHAIN_ID => latest_item.get_chain_id(params),
                        sig if sig == *GET_CHAIN_ID_V1 => latest_item.get_chain_id_v1(params),
                        sig if sig == *GET_OPERATOR => latest_item.get_operator(params),
                        sig if sig == *GET_WEBSITE => latest_item.get_website(params),
                        sig if sig == *GET_BLOCK_INTERVAL => latest_item.get_block_interval(params),
                        sig if sig == *GET_ECONOMICAL_MODEL => {
                            latest_item.get_economical_model(params)
                        }
                        sig if sig == *GET_TOKEN_INFO => latest_item.get_token_info(params),
                        sig if sig == *GET_AUTO_EXEC => latest_item.get_auto_exec(params),
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
                        b"sys".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );

                    // debug information, can be ommited
                    // let bin_map = contracts_db
                    //     .get(DataCategory::Contracts, b"sys".to_vec())
                    //     .unwrap();
                    // let str = String::from_utf8(bin_map.unwrap()).unwrap();
                    // let contracts: SystemStore = serde_json::from_str(&str).unwrap();
                    // trace!("System contract system {:?} after update.", contracts);
                }
                return result;
            }
            _ => Err(ContractError::Internal("params error".to_owned())),
        }
    }

    fn create(&self) -> Box<dyn Contract<B>> {
        Box::new(SystemStore::default())
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SysConfig {
    delay_block_number: u64,
    check_permission: bool,
    check_send_tx_permission: bool,
    check_create_contract_permission: bool,
    check_quota: bool,
    check_feeback_platform: bool,
    chain_owner: Address,
    chain_name: String,
    chain_id: u64,
    operator: String,
    website: String,
    block_interval: u64,
    economical_model: u64,
    name: String,
    symbol: String,
    avatar: String,
    auto_exec: bool,
}

impl SysConfig {
    pub fn new(
        delay_block_number: u64,
        check_permission: bool,
        check_send_tx_permission: bool,
        check_create_contract_permission: bool,
        check_quota: bool,
        check_feeback_platform: bool,
        chain_owner: Address,
        chain_name: String,
        chain_id: u64,
        operator: String,
        website: String,
        block_interval: u64,
        economical_model: u64,
        name: String,
        symbol: String,
        avatar: String,
        auto_exec: bool,
    ) -> Self {
        SysConfig {
            delay_block_number,
            check_permission,
            check_send_tx_permission,
            check_create_contract_permission,
            check_quota,
            check_feeback_platform,
            chain_owner,
            chain_name,
            chain_id,
            operator,
            website,
            block_interval,
            economical_model,
            name,
            symbol,
            avatar,
            auto_exec,
        }
    }

    pub fn set_chain_name(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: set_chain_name");
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin") {
            if let Ok(param) = ethabi::decode(&[ParamType::String], &params.input[4..]) {
                let param_chain_name = match &param[0] {
                    Token::String(s) => s,
                    _ => unreachable!(),
                };
                self.chain_name = encode_string(&param_chain_name);
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

    pub fn set_operator(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: set_operator");
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin") {
            if let Ok(param) = ethabi::decode(&[ParamType::String], &params.input[4..]) {
                let param_operator = match &param[0] {
                    Token::String(s) => s,
                    _ => unreachable!(),
                };
                self.operator = encode_string(&param_operator);
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

    pub fn set_website(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: set_website");
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin") {
            if let Ok(param) = ethabi::decode(&[ParamType::String], &params.input[4..]) {
                let param_website = match &param[0] {
                    Token::String(s) => s,
                    _ => unreachable!(),
                };
                self.website = encode_string(&param_website);
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

    pub fn set_block_interval(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: set_block_interval");
        if check::only_admin(params, context, contracts_db.clone()).expect("Not admin") {
            let param = U256::from(&params.input[4..]);
            self.block_interval = param.as_u64();
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

    pub fn get_permission_check(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_permission_check");
        if self.check_permission {
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ))
    }

    pub fn get_send_tx_permission_check(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_permission_check");
        if self.check_send_tx_permission {
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ))
    }

    pub fn get_create_contract_permission_check(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_permission_check");
        if self.check_create_contract_permission {
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ))
    }

    pub fn get_quota_check(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_quota_check");
        if self.check_quota {
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ))
    }

    pub fn get_fee_back_platform_check(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_fee_back_platform_check");
        if self.check_feeback_platform {
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ))
    }

    pub fn get_chain_owner(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_chain_owner");
        return Ok(InterpreterResult::Normal(
            H256::from(self.chain_owner).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn get_chain_name(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_chain_name");
        let bin = hex::decode(self.chain_name.clone()).unwrap();
        return Ok(InterpreterResult::Normal(bin, params.gas_limit, vec![]));
    }

    pub fn get_chain_id(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_chain_id");
        let res = U256::from(0);
        return Ok(InterpreterResult::Normal(
            H256::from(res).to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn get_chain_id_v1(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_chain_id_v1");
        let res = U256::from(self.chain_id);
        return Ok(InterpreterResult::Normal(
            H256::from(res).to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn get_operator(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_operator");
        let bin = hex::decode(self.operator.clone()).unwrap();
        return Ok(InterpreterResult::Normal(bin, params.gas_limit, vec![]));
    }

    pub fn get_website(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_website");
        let bin = hex::decode(self.website.clone()).unwrap();
        return Ok(InterpreterResult::Normal(bin, params.gas_limit, vec![]));
    }

    pub fn get_block_interval(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_block_interval");
        let res = U256::from(self.block_interval);
        return Ok(InterpreterResult::Normal(
            H256::from(res).to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn get_economical_model(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_economical_model");
        let res = U256::from(self.economical_model);
        return Ok(InterpreterResult::Normal(
            H256::from(res).to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn get_token_info(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_token_info");
        let mut tokens = Vec::new();
        tokens.push(Token::String(self.name.clone()));
        tokens.push(Token::String(self.symbol.clone()));
        tokens.push(Token::String(self.avatar.clone()));
        let res = ethabi::encode(&tokens);

        return Ok(InterpreterResult::Normal(
            res.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn get_auto_exec(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_auto_exec");
        if self.auto_exec {
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }

        Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ))
    }

    pub fn get_delay_block_number(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract: get_delay_block_number");
        let res = U256::from(self.delay_block_number);
        return Ok(InterpreterResult::Normal(
            H256::from(res).to_vec(),
            params.gas_limit,
            vec![],
        ));
    }
}

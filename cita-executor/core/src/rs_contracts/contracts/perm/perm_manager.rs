use crate::rs_contracts::contracts::tool::{
    check_same_length, clean_0x, extract_to_u32, get_latest_key,
};

use cita_types::{Address, H256};
use cita_vm::evm::{InterpreterParams, InterpreterResult, Log};
use common_types::context::Context;
use common_types::errors::ContractError;

use crate::rs_contracts::contracts::group::group_manager::GroupStore;
use crate::rs_contracts::contracts::perm::build_in_perm;
use crate::rs_contracts::contracts::perm::Permission;
use crate::rs_contracts::contracts::tool::check;
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
use std::collections::BTreeSet;
use std::sync::Arc;
use tiny_keccak::keccak256;

use crate::cita_executive::create_address_from_address_and_nonce;
use cita_types::traits::LowerHex;
use cita_vm::state::StateObjectInfo;
use common_types::reserved_addresses;
use ethabi::token::LenientTokenizer;
use ethabi::token::Tokenizer;

use crate::contracts::tools::method;
lazy_static! {
    static ref NEW_PERM: u32 = method::encode_to_u32(b"newPermission(bytes32,address[],bytes4[])");
    static ref DEL_PERM: u32 = method::encode_to_u32(b"deletePermission(address)");
    static ref UPDATE_PERM_NAME: u32 =
        method::encode_to_u32(b"updatePermissionName(address,bytes32)");
    static ref ADD_RESOURCES: u32 =
        method::encode_to_u32(b"addResources(address,address[],bytes4[])");
    static ref DEL_RESOURCES: u32 =
        method::encode_to_u32(b"deleteResources(address,address[],bytes4[])");
    static ref SET_AUTH: u32 = method::encode_to_u32(b"setAuthorization(address,address)");
    static ref SET_AUTHS: u32 = method::encode_to_u32(b"setAuthorizations(address,address[])");
    static ref CANCEL_AUTH: u32 = method::encode_to_u32(b"cancelAuthorization(address,address)");
    static ref CANCEL_AUTHS: u32 =
        method::encode_to_u32(b"cancelAuthorizations(address,address[])");
    static ref CLEAR_AUTHS: u32 = method::encode_to_u32(b"clearAuthorization(address)");
    static ref IN_PERMS: u32 = method::encode_to_u32(b"inPermission(address,address,bytes4)");
    static ref QUERY_NAME: u32 = method::encode_to_u32(b"queryName(address)");
    static ref QUERY_RESOURCE: u32 = method::encode_to_u32(b"queryResource(address)");
    static ref CHECK_PERM: u32 = method::encode_to_u32(b"checkPermission(address,address)");
    static ref CHECK_RESOURCE: u32 =
        method::encode_to_u32(b"checkResource(address,address,bytes4)");
    static ref QUERY_PERMS: u32 = method::encode_to_u32(b"queryPermissions(address)");
    static ref QUERY_ALL_ACCOUNTS: u32 = method::encode_to_u32(b"queryAllAccounts()");
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PermStore {
    // key -> height, value -> json(PermissionManager)
    pub contracts: BTreeMap<u64, Option<String>>,
}

impl PermStore {
    pub fn init(
        admin: Address,
        perm_contracts: BTreeMap<Address, String>,
        contracts_db: Arc<ContractsDB>,
    ) -> Self {
        let mut perm_store = PermStore::default();

        let mut perm_manager = PermManager::default();
        for (addr, contract) in perm_contracts.iter() {
            let p: Permission = serde_json::from_str(&contract).unwrap();
            perm_manager.perm_collection.insert(*addr, p);
        }

        let mut account_own_perms = BTreeMap::new();
        let mut super_admin_perms = BTreeSet::new();
        for p in build_in_perm::BUILD_IN_PERMS.iter() {
            super_admin_perms.insert(Address::from(*p));
        }
        account_own_perms.insert(admin, super_admin_perms);
        let mut group_perms = BTreeSet::new();
        group_perms.insert(Address::from(build_in_perm::SEND_TX_ADDRESS));
        group_perms.insert(Address::from(build_in_perm::CREATE_CONTRACT_ADDRESS));
        account_own_perms.insert(
            Address::from(build_in_perm::ROOT_GROUP_ADDRESS),
            group_perms,
        );
        perm_manager.account_own_perms = account_own_perms;

        let str = serde_json::to_string(&perm_manager).unwrap();
        perm_store.contracts.insert(0, Some(str));

        let s = serde_json::to_string(&perm_store).unwrap();
        let _ = contracts_db.insert(
            DataCategory::Contracts,
            b"perm".to_vec(),
            s.as_bytes().to_vec(),
        );

        perm_store
    }

    pub fn get_latest_item(
        current_height: u64,
        contracts_db: Arc<ContractsDB>,
    ) -> (Option<PermStore>, Option<PermManager>) {
        if let Some(store) = contracts_db
            .get(DataCategory::Contracts, b"perm".to_vec())
            .expect("get store error")
        {
            let contract_map: PermStore = serde_json::from_slice(&store).unwrap();
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

            let latest_perm_manager: PermManager =
                serde_json::from_str(&(*bin).clone().unwrap()).unwrap();
            return (Some(contract_map), Some(latest_perm_manager));
        }

        (None, None)
    }

    pub fn update_admin_permissions<B: DB>(
        params: &InterpreterParams,
        context: &Context,
        old_admin: Address,
        new_admin: Address,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) {
        match PermStore::get_latest_item(context.block_number, contracts_db.clone()) {
            (Some(mut contract_map), Some(mut latest_perm_manager)) => {
                latest_perm_manager.update_admin_permissions(old_admin, new_admin);

                let str = serde_json::to_string(&latest_perm_manager).unwrap();
                let updated_hash = keccak256(&str.as_bytes().to_vec());
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
                    b"perm".to_vec(),
                    map_str.as_bytes().to_vec(),
                );
            }
            _ => unreachable!(),
        }
    }
}

impl<B: DB> Contract<B> for PermStore {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: enter execute");
        let (contract_map, latest_perm_manager) =
            PermStore::get_latest_item(context.block_number, contracts_db.clone());
        match (contract_map, latest_perm_manager) {
            (Some(mut contract_map), Some(mut latest_perm_manager)) => {
                trace!(
                    "System contracts - permission - params input {:?}",
                    params.input
                );
                let mut updated = false;
                let result =
                    extract_to_u32(&params.input[..]).and_then(|signature| match signature {
                        sig if sig == *NEW_PERM => latest_perm_manager.new_permission(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                            state.clone(),
                        ),
                        sig if sig == *DEL_PERM => latest_perm_manager.del_permission(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *UPDATE_PERM_NAME => latest_perm_manager
                            .update_permission_name(
                                params,
                                &mut updated,
                                context,
                                contracts_db.clone(),
                            ),
                        sig if sig == *ADD_RESOURCES => latest_perm_manager
                            .add_permission_resources(
                                params,
                                &mut updated,
                                context,
                                contracts_db.clone(),
                            ),
                        sig if sig == *DEL_RESOURCES => latest_perm_manager
                            .del_permission_resources(
                                params,
                                &mut updated,
                                context,
                                contracts_db.clone(),
                            ),
                        sig if sig == *SET_AUTHS => latest_perm_manager.set_authorizations(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *SET_AUTH => latest_perm_manager.set_authorization(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *CANCEL_AUTHS => latest_perm_manager.cancel_authorizations(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *CANCEL_AUTH => latest_perm_manager.cancel_authorization(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *CLEAR_AUTHS => latest_perm_manager.clear_authorization(
                            params,
                            &mut updated,
                            context,
                            contracts_db.clone(),
                        ),
                        sig if sig == *CHECK_PERM => latest_perm_manager.check_permission(params),
                        sig if sig == *CHECK_RESOURCE => latest_perm_manager.check_resource(params),
                        sig if sig == *QUERY_PERMS => latest_perm_manager.query_permssions(params),
                        sig if sig == *QUERY_ALL_ACCOUNTS => {
                            latest_perm_manager.query_all_accounts(params)
                        }
                        sig if sig == *QUERY_RESOURCE => latest_perm_manager.query_resource(params),
                        sig if sig == *QUERY_NAME => latest_perm_manager.query_name(params),
                        sig if sig == *IN_PERMS => latest_perm_manager.in_permission(params),
                        _ => panic!("Invalid function signature {} ", signature),
                    });

                if result.is_ok() & updated {
                    let new_perm_manager = latest_perm_manager;
                    let str = serde_json::to_string(&new_perm_manager).unwrap();
                    trace!("hash content is {:?}", str);
                    let updated_hash = keccak256(&str.as_bytes().to_vec());
                    trace!("updated hash is {:?}", updated_hash);

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
                        .insert(context.block_number, Some(str.clone()));

                    let map_str = serde_json::to_string(&contract_map).unwrap();
                    let _ = contracts_db.insert(
                        DataCategory::Contracts,
                        b"perm".to_vec(),
                        map_str.as_bytes().to_vec(),
                    );

                    // debug information, can be ommited
                    // let bin_map = contracts_db
                    //     .get(DataCategory::Contracts, b"permission-contract".to_vec())
                    //     .unwrap();
                    // let str = String::from_utf8(bin_map.unwrap()).unwrap();
                    // let contracts: PermStore = serde_json::from_str(&str).unwrap();
                    // trace!("System contract permission {:?} after update.", contracts);
                }
                return result;
            }
            _ => Err(ContractError::Internal("params error".to_owned())),
        }
    }

    fn create(&self) -> Box<dyn Contract<B>> {
        Box::new(PermStore::default())
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PermManager {
    pub perm_collection: BTreeMap<Address, Permission>,
    pub account_own_perms: BTreeMap<Address, BTreeSet<Address>>,
}

impl PermManager {
    pub fn new(super_admin: Address) -> Self {
        let mut account_own_perms = BTreeMap::new();

        let mut super_admin_perms = BTreeSet::new();
        for p in build_in_perm::BUILD_IN_PERMS.iter() {
            super_admin_perms.insert(Address::from(*p));
        }
        account_own_perms.insert(super_admin, super_admin_perms);

        let mut group_perms = BTreeSet::new();
        group_perms.insert(Address::from(build_in_perm::SEND_TX_ADDRESS));
        group_perms.insert(Address::from(build_in_perm::CREATE_CONTRACT_ADDRESS));
        account_own_perms.insert(
            Address::from(build_in_perm::ROOT_GROUP_ADDRESS),
            group_perms,
        );

        PermManager {
            account_own_perms,
            perm_collection: BTreeMap::new(),
        }
    }

    pub fn new_permission<B: DB>(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: new permission");
        let new_permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[0]);
        if !self.have_permission(
            params.sender,
            new_permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }

        let tokens = vec![
            ParamType::FixedBytes(32),
            ParamType::Array(Box::new(ParamType::Address)),
            ParamType::Array(Box::new(ParamType::FixedBytes(4))),
        ];
        if let Ok(args) = ethabi::decode(&tokens, &params.input[4..]) {
            match (&args[0], &args[1], &args[2]) {
                (Token::FixedBytes(name), Token::Array(addrs), Token::Array(funcs)) => {
                    let perm_name = H256::from_slice(name);
                    let perm_addrs = addrs
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();
                    let perm_funcs = funcs
                        .iter()
                        .map(|i| match i {
                            Token::FixedBytes(x) => x.clone(),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<_>>();

                    // len(perm_addrs) == len(perm_funcs)
                    if !check_same_length(&perm_addrs, &perm_funcs) {
                        error!("The const array length not equal to the funcs array");
                        return Ok(InterpreterResult::Normal(
                            H256::from(0).0.to_vec(),
                            params.gas_limit,
                            vec![],
                        ));
                    }
                    trace!("perm_name {:?}", perm_name);
                    trace!("perm_addrs {:?}", perm_addrs);
                    trace!("perm_funcs {:?}", perm_funcs);

                    let perm = Permission::new(perm_name.lower_hex(), perm_addrs, perm_funcs);
                    let nonce = state
                        .borrow_mut()
                        .nonce(&Address::from(reserved_addresses::PERMISSION_CREATOR))
                        .unwrap();
                    let perm_address = create_address_from_address_and_nonce(
                        &Address::from(reserved_addresses::PERMISSION_CREATOR),
                        &nonce,
                    );
                    state
                        .borrow_mut()
                        .inc_nonce(&Address::from(reserved_addresses::PERMISSION_CREATOR))
                        .unwrap();
                    trace!("perm address created in new_permission {:?}", perm_address);
                    self.perm_collection.insert(perm_address, perm);

                    let mut logs = Vec::new();
                    let mut topics = Vec::new();
                    let signature = "newPermission(bytes32,address[],bytes4[])".as_bytes();
                    topics.push(H256::from(keccak256(signature)));
                    topics.push(H256::from(perm_address));
                    let log = Log(perm_address, topics, vec![]);
                    logs.push(log);

                    *changed = true;
                    return Ok(InterpreterResult::Normal(
                        H256::from(perm_address).0.to_vec(),
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

    pub fn del_permission(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: del permission",);

        let delete_permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[1]);
        if !self.have_permission(
            params.sender,
            delete_permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }

        let perm_address = Address::from(&params.input[16..36]);
        if check::check_not_build_in(perm_address) {
            self.perm_collection.remove(&perm_address);

            // update accounts permissions
            for (_account, perms) in self.account_own_perms.iter_mut() {
                perms.remove(&perm_address);
            }

            *changed = true;
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                vec![],
            ));
        }
        warn!(
            "permission {:?} is build in contracts, can not be deleted.",
            perm_address
        );
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn update_permission_name(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: update permission name",);

        let permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[2]);
        if !self.have_permission(
            params.sender,
            permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }
        let perm_address = Address::from(&params.input[16..36]);
        let perm_name = H256::from(&params.input[36..68]).lower_hex();
        trace!(
            "params decoded: perm_address: {:?}, perm_name: {:?}",
            perm_address,
            perm_name
        );
        if let Some(perm) = self.perm_collection.get_mut(&perm_address) {
            perm.update_name(&perm_name);
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

    pub fn add_permission_resources(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: add_permission_resource",);

        let permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[2]);
        if !self.have_permission(
            params.sender,
            permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }

        let tokens = vec![
            ParamType::Address,
            ParamType::Array(Box::new(ParamType::Address)),
            ParamType::Array(Box::new(ParamType::FixedBytes(4))),
        ];

        if let Ok(args) = ethabi::decode(&tokens, &&params.input[4..]) {
            match (&args[0], &args[1], &args[2]) {
                (Token::Address(perm), Token::Array(addrs), Token::Array(funcs)) => {
                    let perm_address = Address::from_slice(&perm.to_vec());
                    let perm_conts = addrs
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();
                    let perm_funcs = funcs
                        .iter()
                        .map(|i| match i {
                            Token::FixedBytes(x) => x.clone(),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<_>>();
                    trace!(
                        "params decoded: account: {:?}, permissions: {:?} resource: {:?}",
                        perm_address,
                        perm_conts,
                        perm_funcs
                    );
                    if let Some(p) = self.perm_collection.get_mut(&perm_address) {
                        p.add_resources(perm_conts, perm_funcs);
                        *changed = true;
                        return Ok(InterpreterResult::Normal(
                            H256::from(1).0.to_vec(),
                            params.gas_limit,
                            vec![],
                        ));
                    }
                }
                _ => unreachable!(),
            }
        }
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn del_permission_resources(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: del_permission_resource",);

        let permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[2]);
        if !self.have_permission(
            params.sender,
            permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }

        let tokens = vec![
            ParamType::Address,
            ParamType::Array(Box::new(ParamType::Address)),
            ParamType::Array(Box::new(ParamType::FixedBytes(4))),
        ];

        if let Ok(args) = ethabi::decode(&tokens, &&params.input[4..]) {
            match (&args[0], &args[1], &args[2]) {
                (Token::Address(perm), Token::Array(addrs), Token::Array(funcs)) => {
                    let perm_address = Address::from_slice(&perm.to_vec());
                    let perm_conts = addrs
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();
                    let perm_funcs = funcs
                        .iter()
                        .map(|i| match i {
                            Token::FixedBytes(x) => x.clone(),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<_>>();
                    trace!(
                        "params decoded: account: {:?}, permissions: {:?} resource: {:?}",
                        perm_address,
                        perm_conts,
                        perm_funcs
                    );
                    if let Some(p) = self.perm_collection.get_mut(&perm_address) {
                        p.delete_resources(perm_conts, perm_funcs);
                        *changed = true;
                        return Ok(InterpreterResult::Normal(
                            H256::from(1).0.to_vec(),
                            params.gas_limit,
                            vec![],
                        ));
                    }
                }
                _ => unreachable!(),
            }
        }
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn set_authorizations(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: set_authorizations",);

        let permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[3]);
        if !self.have_permission(
            params.sender,
            permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }

        let tokens = vec![
            ParamType::Address,
            ParamType::Array(Box::new(ParamType::Address)),
        ];

        if let Ok(args) = ethabi::decode(&tokens, &&params.input[4..]) {
            match (&args[0], &args[1]) {
                (Token::Address(account), Token::Array(addrs)) => {
                    let account = Address::from_slice(&account.to_vec());
                    let perm_conts = addrs
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();

                    trace!(
                        "params decoded: account: {:?}, permissions: {:?}",
                        account,
                        perm_conts
                    );
                    for p in perm_conts.iter() {
                        if let Some(perms) = self.account_own_perms.get_mut(&account) {
                            perms.insert(*p);
                        } else {
                            let mut set = BTreeSet::new();
                            set.insert(*p);
                            self.account_own_perms.insert(account, set);
                        }
                    }
                    *changed = true;
                    return Ok(InterpreterResult::Normal(
                        H256::from(1).0.to_vec(),
                        params.gas_limit,
                        vec![],
                    ));
                }
                _ => unreachable!(),
            }
        }
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn cancel_authorizations(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: cancel_authorizations");

        let permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[4]);
        if !self.have_permission(
            params.sender,
            permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }

        let tokens = vec![
            ParamType::Address,
            ParamType::Array(Box::new(ParamType::Address)),
        ];

        if let Ok(args) = ethabi::decode(&tokens, &&params.input[4..]) {
            match (&args[0], &args[1]) {
                (Token::Address(account), Token::Array(addrs)) => {
                    let account = Address::from_slice(&account.to_vec());
                    let perm_conts = addrs
                        .iter()
                        .map(|i| match i {
                            Token::Address(x) => Address::from_slice(x),
                            _ => unreachable!(),
                        })
                        .collect::<Vec<Address>>();
                    trace!(
                        "params decoded: account: {:?}, permissions: {:?}",
                        account,
                        perm_conts
                    );
                    if let Some(perms) = self.account_own_perms.get_mut(&account) {
                        for p in perm_conts {
                            perms.remove(&p);
                        }
                        *changed = true;
                        return Ok(InterpreterResult::Normal(
                            H256::from(1).0.to_vec(),
                            params.gas_limit,
                            vec![],
                        ));
                    }
                }
                _ => unreachable!(),
            }
        }
        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }

    pub fn set_authorization(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: set_authorization",);

        let permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[3]);
        if !self.have_permission(
            params.sender,
            permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }

        let account = Address::from(&params.input[16..36]);
        let permission = Address::from(&params.input[48..68]);
        trace!(
            "params decoded: account: {:?}, permission: {:?}",
            account,
            permission
        );

        if let Some(perms) = self.account_own_perms.get_mut(&account) {
            perms.insert(permission);
        } else {
            let mut set = BTreeSet::new();
            set.insert(permission);
            self.account_own_perms.insert(account, set);
        }
        *changed = true;
        return Ok(InterpreterResult::Normal(
            H256::from(1).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn cancel_authorization(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: cancel_authorization");

        let permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[4]);
        if !self.have_permission(
            params.sender,
            permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }

        let account = Address::from(&params.input[16..36]);
        let permission = Address::from(&params.input[48..68]);

        if let Some(perms) = self.account_own_perms.get_mut(&account) {
            perms.remove(&permission);
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

    pub fn clear_authorization(
        &mut self,
        params: &InterpreterParams,
        changed: &mut bool,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: clear_authorization");

        let permission_build_in = Address::from(build_in_perm::BUILD_IN_PERMS[4]);
        if !self.have_permission(
            params.sender,
            permission_build_in,
            context,
            contracts_db.clone(),
        ) {
            return Err(ContractError::Internal(
                "System contract execute error".to_owned(),
            ));
        }

        let account = Address::from(&params.input[16..36]);
        if let Some(perms) = self.account_own_perms.get_mut(&account) {
            perms.clear();
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

    pub fn query_permssions(
        &mut self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: query_permssions");
        let param_address = Address::from_slice(&params.input[16..36]);
        if let Some(permissions) = self.account_own_perms.get(&param_address) {
            let mut perms = Vec::new();
            for p in permissions.iter() {
                perms.push(Token::Address(p.0));
            }

            let mut tokens = Vec::new();
            tokens.push(Token::Array(perms));
            return Ok(InterpreterResult::Normal(
                ethabi::encode(&tokens),
                params.gas_limit,
                vec![],
            ));
        }

        return Ok(InterpreterResult::Normal(vec![], params.gas_limit, vec![]));
    }

    pub fn query_all_accounts(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: query_permssions");
        let mut accounts = Vec::new();
        for k in self.account_own_perms.keys() {
            accounts.push(Token::Address(k.0));
        }

        let mut tokens = Vec::new();
        tokens.push(Token::Array(accounts));

        return Ok(InterpreterResult::Normal(
            ethabi::encode(&tokens),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn query_resource(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: query_resource");
        let perm_address = Address::from(&params.input[16..36]);
        if let Some(p) = self.perm_collection.get(&perm_address) {
            let mut tokens = Vec::new();
            let (conts, funcs) = p.query_resource();

            let mut conts_return = Vec::new();
            let mut funcs_return = Vec::new();
            for i in 0..conts.len() {
                conts_return.push(Token::Address(conts[i].0));
                funcs_return.push(Token::FixedBytes(funcs[i].clone()));
            }

            tokens.push(Token::Array(conts_return));
            tokens.push(Token::Array(funcs_return));
            return Ok(InterpreterResult::Normal(
                ethabi::encode(&tokens),
                params.gas_limit,
                vec![],
            ));
        }
        return Ok(InterpreterResult::Normal(vec![], params.gas_limit, vec![]));
    }

    pub fn query_name(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: query_name");
        let perm_address = Address::from(&params.input[16..36]);
        if let Some(p) = self.perm_collection.get(&perm_address) {
            let name = p.query_name();
            trace!("permission name {:?}", name);
            trace!("permission name bin {:?}", name);
            // let mut res = H256::from(0);
            // res.clone_from_slice(&name.as_bytes());
            let res =
                LenientTokenizer::tokenize(&ParamType::FixedBytes(32), &clean_0x(&name)).unwrap();
            return Ok(InterpreterResult::Normal(
                res.clone().to_fixed_bytes().unwrap(),
                params.gas_limit,
                vec![],
            ));
        }
        return Ok(InterpreterResult::Normal(vec![], params.gas_limit, vec![]));
    }

    pub fn in_permission(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: in_permission");
        let perm_address = Address::from(&params.input[16..36]);
        let resource_cont = Address::from(&params.input[48..68]);
        let resource_func = &params.input[68..72];
        trace!(
            "Check_resource, perm_address: {:?}, resource_cont: {:?}, resource_func {:?}",
            perm_address,
            resource_cont,
            resource_func
        );

        if let Some(perm) = self.perm_collection.get(&perm_address) {
            if perm.in_permission(resource_cont, resource_func.to_vec()) {
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

    pub fn check_resource(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: check_resource");
        let account = Address::from(&params.input[16..36]);
        let resource_cont = Address::from(&params.input[48..68]);
        let resource_func = &params.input[68..72];
        trace!(
            "Check_resource, account: {:?}, resource_cont: {:?}, resource_func {:?}",
            account,
            resource_cont,
            resource_func
        );

        if let Some(perms_address) = self.account_own_perms.get(&account) {
            for p in perms_address.iter() {
                if let Some(permission) = self.perm_collection.get(p) {
                    if permission.in_permission(resource_cont, resource_func.to_vec()) {
                        return Ok(InterpreterResult::Normal(
                            H256::from(1).0.to_vec(),
                            params.gas_limit,
                            vec![],
                        ));
                    }
                }
            }
        }

        return Ok(InterpreterResult::Normal(
            H256::from(0).0.to_vec(),
            params.gas_limit,
            vec![],
        ));
    }

    pub fn check_permission(
        &self,
        params: &InterpreterParams,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("Permission contract: check_permission");
        let account = Address::from(&params.input[16..36]);
        let permission = Address::from(&params.input[48..68]);

        trace!(
            "Check_permission, account: {:?}, permission: {:?}",
            account,
            permission
        );
        if let Some(perms) = self.account_own_perms.get(&account) {
            if perms.contains(&permission) {
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

    pub fn update_admin_permissions(&mut self, old_admin: Address, new_admin: Address) {
        // give new admin buildin permissions
        let mut super_admin_perms = BTreeSet::new();
        for p in build_in_perm::BUILD_IN_PERMS.iter() {
            super_admin_perms.insert(Address::from(*p));
        }
        self.account_own_perms.insert(new_admin, super_admin_perms);

        // remove old admin buildin permissions
        if let Some(perms) = self.account_own_perms.get_mut(&old_admin) {
            for i in 0..build_in_perm::BUILD_IN_PERMS.len() {
                if i != 13 && i != 14 {
                    perms.remove(&Address::from(build_in_perm::BUILD_IN_PERMS[i]));
                }
            }
        }
    }

    fn have_permission(
        &self,
        sender: Address,
        perm_address: Address,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
    ) -> bool {
        if let Some(perms) = self.account_own_perms.get(&sender) {
            // check sender
            if perms.contains(&perm_address) {
                return true;
            }
        } else if let Some(groups) =
            GroupStore::get_account_groups(sender, context, contracts_db.clone())
        {
            // check group
            for g in groups.iter() {
                if let Some(perms) = self.account_own_perms.get(&g) {
                    if perms.contains(&perm_address) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

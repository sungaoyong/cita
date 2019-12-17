// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::libexecutor::block::Block;
use crate::libexecutor::executor::{CitaDB, CitaTrieDB};
use crate::types::db_indexes;
use crate::types::db_indexes::DBIndex;
use crate::types::reserved_addresses;
use cita_database::{DataCategory, Database};
use cita_types::traits::ConvertType;
use cita_types::{Address, H256, U256};
use cita_vm::state::State as CitaState;
use crypto::digest::Digest;
use crypto::md5::Md5;
use rlp::encode;
use serde_json;
use std::cell::RefCell;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use std::u64;

use crate::rs_contracts::contracts::group::group_manager::{GroupManager, GroupStore};
use crate::rs_contracts::contracts::perm::{PermStore, Permission};
use crate::rs_contracts::contracts::role::role_manager::{RoleManager, RoleStore};
use crate::rs_contracts::contracts::sys::{
    Admin, AutoExec, BatchTx, EmergencyIntervention, NodeManager, Price, QuotaManager, SysConfig,
    Version,
};

use crate::rs_contracts::contracts::sys::{
    AdminStore, AutoStore, EmergStore, NodeStore, PriceStore, QuotaStore, SystemStore, VersionStore,
};
use crate::rs_contracts::contracts::tool::utils::{
    encode_string, hex_to_integer, string_to_bool, string_to_static_str, string_to_u64,
};
use crate::rs_contracts::factory::ContractsFactory;
use crate::rs_contracts::storage::db_contracts::ContractsDB;
use std::collections::BTreeMap;
use tiny_keccak::keccak256;

#[cfg(feature = "privatetx")]
use zktx::set_param_path;

#[derive(Debug, PartialEq, Deserialize, Clone)]
pub struct Contract {
    pub nonce: String,
    pub code: String,
    pub storage: BTreeMap<String, String>,
    pub value: Option<U256>,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Spec {
    pub alloc: BTreeMap<String, Contract>,
    pub prevhash: H256,
    pub timestamp: u64,
}

#[derive(Debug, PartialEq)]
pub struct Genesis {
    pub spec: Spec,
    pub block: Block,
}

impl Genesis {
    pub fn init(path: &str) -> Genesis {
        let config_file = File::open(path).unwrap();
        let fconfig = BufReader::new(config_file);
        let spec: Spec = serde_json::from_reader(fconfig).expect("Failed to load genesis.");

        // check resource with pre hash in genesis
        // default pre hash is zero
        let mut pre_hash = H256::zero();
        // resource folder at the same place with genesis file
        let resource_path = Path::new(path).parent().unwrap().join("resource");
        #[cfg(feature = "privatetx")]
        {
            set_param_path(resource_path.join("PARAMS").to_str().unwrap());
        }
        if resource_path.exists() {
            let file_list_path = resource_path.join("files.list");
            if file_list_path.exists() {
                let file_list = File::open(file_list_path).unwrap();
                let mut buf_reader = BufReader::new(file_list);
                let mut contents = String::new();
                buf_reader.read_to_string(&mut contents).unwrap();
                let mut hasher = Md5::new();
                for p in contents.lines() {
                    let path = resource_path.join(p);
                    let file = File::open(path).unwrap();
                    let mut buf_reader = BufReader::new(file);
                    let mut buf = Vec::new();
                    buf_reader.read_to_end(&mut buf).unwrap();
                    hasher.input(&buf);
                }
                let mut hash_str = "0x00000000000000000000000000000000".to_string();
                hash_str += &hasher.result_str();
                info!("resource hash {}", hash_str);
                pre_hash = H256::from_unaligned(hash_str.as_str()).unwrap();
            }
        }

        assert_eq!(pre_hash, spec.prevhash);

        Genesis {
            spec,
            block: Block::default(),
        }
    }

    pub fn lazy_execute(
        &mut self,
        state_db: Arc<CitaTrieDB>,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<(), String> {
        let state = CitaState::from_existing(
            Arc::<CitaTrieDB>::clone(&state_db),
            *self.block.state_root(),
        )
        .expect("Can not get state from db!");
        let start = Instant::now();

        let state = Arc::new(RefCell::new(state));
        let mut contracts_factory = ContractsFactory::new(state.clone(), contracts_db.clone());

        self.block.set_version(0);
        self.block.set_parent_hash(self.spec.prevhash);
        self.block.set_timestamp(self.spec.timestamp);
        self.block.set_number(0);

        info!("This is the first time to init executor, and it will init contracts on height 0");
        trace!("**** begin **** \n");
        let mut permission_contracts = BTreeMap::new();
        let mut admin = Address::default();

        for (address, contract) in self.spec.alloc.clone() {
            let address = Address::from_unaligned(address.as_str()).unwrap();
            if address == Address::from(reserved_addresses::ADMIN) {
                // admin contract
                for (key, value) in contract.storage.clone() {
                    if *key == "admin".to_string() {
                        admin = Address::from_unaligned(value.as_str()).unwrap();
                        let contract_admin = Admin::new(admin);
                        let str = serde_json::to_string(&contract_admin).unwrap();

                        let a = AdminStore::init(str, contracts_db.clone());
                        contracts_factory.register(address, Box::new(a));
                    }
                }
            } else if address == Address::from(reserved_addresses::QUOTA_MANAGER) {
                // admin contract
                for (key, value) in contract.storage.clone() {
                    if *key == "admin".to_string() {
                        let admin = Address::from_unaligned(value.as_str()).unwrap();
                        let contract_admin = QuotaManager::new(admin);
                        let str = serde_json::to_string(&contract_admin).unwrap();

                        let a = QuotaStore::init(str, contracts_db.clone());
                        contracts_factory.register(address, Box::new(a));
                    }
                }
            } else if address == Address::from(reserved_addresses::PRICE_MANAGEMENT) {
                for (key, value) in contract.storage.clone() {
                    if *key == "quota_price".to_string() {
                        let price = U256::from_dec_str(&value).unwrap();
                        let contract_price = Price::new(price);
                        let str = serde_json::to_string(&contract_price).unwrap();

                        let a = PriceStore::init(str, contracts_db.clone());
                        contracts_factory.register(address, Box::new(a));
                    }
                }
            } else if address == Address::from(reserved_addresses::VERSION_MANAGEMENT) {
                for (key, value) in contract.storage.clone() {
                    if *key == "version".to_string() {
                        let version = U256::from_dec_str(&value).unwrap();
                        let contract_version = Version::new(version);
                        let str = serde_json::to_string(&contract_version).unwrap();

                        let a = VersionStore::init(str, contracts_db.clone());
                        contracts_factory.register(address, Box::new(a));
                    }
                }
            } else if address == Address::from(reserved_addresses::NODE_MANAGER) {
                let mut nodes = Vec::new();
                let mut stakes = Vec::new();
                for (key, value) in contract.storage.clone() {
                    nodes.push(Address::from_unaligned(&key).unwrap());
                    stakes.push(U256::from_dec_str(&value).unwrap());
                }

                let node_manager = NodeManager::new(nodes, stakes);
                let str = serde_json::to_string(&node_manager).unwrap();

                let a = NodeStore::init(str, contracts_db.clone());
                contracts_factory.register(address, Box::new(a));
            } else if address == Address::from(reserved_addresses::GROUP) {
                let mut accounts = Vec::new();
                let mut parent = Address::default();
                let mut name = String::default();
                for (key, value) in contract.storage.clone() {
                    if *key == "parent".to_string() {
                        parent = Address::from_unaligned(&value).unwrap();
                    } else if *key == "name".to_string() {
                        name = value;
                    } else {
                        accounts.push(Address::from_unaligned(&value).unwrap());
                    }
                }
                let group_manager = GroupManager::new(&name, parent, accounts);
                let str = serde_json::to_string(&group_manager).unwrap();

                let a = GroupStore::init(str, contracts_db.clone());
                contracts_factory.register(address, Box::new(a));
            } else if address == Address::from(reserved_addresses::SYS_CONFIG) {
                let auto_exec = contract
                    .storage
                    .get("auto_exec")
                    .expect("get storage error");
                let delay_block_number = contract
                    .storage
                    .get("delay_block_number")
                    .expect("get storage error");
                let avatar = contract.storage.get("avatar").expect("get storage error");
                let symbol = contract.storage.get("symbol").expect("get storage error");
                let block_interval = contract
                    .storage
                    .get("block_interval")
                    .expect("get storage error");
                let chain_id = contract.storage.get("chain_id").expect("get storage error");
                let chain_name = contract
                    .storage
                    .get("chain_name")
                    .expect("get storage error");
                let chain_owner = contract
                    .storage
                    .get("chain_owner")
                    .expect("get storage error");
                let check_call_permission = contract
                    .storage
                    .get("check_call_permission")
                    .expect("get storage error");
                let check_create_contract_permission = contract
                    .storage
                    .get("check_create_contract_permission")
                    .expect("get storage error");
                let check_fee_back_platform = contract
                    .storage
                    .get("check_fee_back_platform")
                    .expect("get storage error");
                let check_quota = contract
                    .storage
                    .get("check_quota")
                    .expect("get storage error");
                let check_send_tx_permission = contract
                    .storage
                    .get("check_send_tx_permission")
                    .expect("get storage error");
                let economical_model = contract
                    .storage
                    .get("economical_model")
                    .expect("get storage error");
                let name = contract.storage.get("name").expect("get storage error");
                let operator = contract.storage.get("operator").expect("get storage error");
                let website = contract.storage.get("website").expect("get storage error");

                trace!("Block interval is {:?}", block_interval);
                trace!("Block interval after {:?}", string_to_u64(block_interval));

                let system_config = SysConfig::new(
                    string_to_u64(delay_block_number),
                    string_to_bool(check_call_permission),
                    string_to_bool(check_send_tx_permission),
                    string_to_bool(check_create_contract_permission),
                    string_to_bool(check_quota),
                    string_to_bool(check_fee_back_platform),
                    Address::from(string_to_static_str(chain_owner.to_string())),
                    encode_string(chain_name),
                    string_to_u64(chain_id),
                    encode_string(operator),
                    encode_string(website),
                    hex_to_integer(block_interval),
                    string_to_u64(economical_model),
                    name.to_string(),
                    symbol.to_string(),
                    avatar.to_string(),
                    string_to_bool(auto_exec),
                );
                let str = serde_json::to_string(&system_config).unwrap();
                let a = SystemStore::init(str, contracts_db.clone());
                contracts_factory.register(address, Box::new(a));
            } else if is_permssion_contract(address) {
                let mut perm_name = String::default();
                let mut conts = Vec::new();
                let mut funcs = Vec::new();

                for (key, value) in contract.storage.clone() {
                    trace!("===> permission contract key {:?}", key);
                    if *key == "perm_name".to_string() {
                        perm_name = value;
                    } else {
                        let addr = Address::from_unaligned(value.as_str()).unwrap();
                        conts.push(addr);
                        let hash_key;
                        if addr == Address::from(reserved_addresses::PERMISSION_SEND_TX)
                            || addr == Address::from(reserved_addresses::PERMISSION_CREATE_CONTRACT)
                        {
                            hash_key = [0; 4].to_vec();
                        } else {
                            hash_key = keccak256(key.as_bytes()).to_vec()[0..4].to_vec();
                        }
                        funcs.push(hash_key);
                    }
                }

                let permission = Permission::new(perm_name, conts, funcs);
                let str = serde_json::to_string(&permission).unwrap();
                permission_contracts.insert(address, str);
            } else {
                trace!("contracts address {:?}", address);
            }
        }
        // register emergency intervention
        let emerg_contract = EmergencyIntervention::default();
        let str = serde_json::to_string(&emerg_contract).unwrap();
        let a = EmergStore::init(str, contracts_db.clone());
        contracts_factory.register(
            Address::from(reserved_addresses::EMERGENCY_INTERVENTION),
            Box::new(a),
        );

        // register auto exec contract
        let auto_exec = AutoExec::default();
        let str = serde_json::to_string(&auto_exec).unwrap();
        let a = AutoStore::init(str, contracts_db.clone());
        contracts_factory.register(Address::from(reserved_addresses::AUTO_EXEC), Box::new(a));

        // register batch tx
        let a = BatchTx::default();
        contracts_factory.register(Address::from(reserved_addresses::BATCH_TX), Box::new(a));

        // register role manager
        let role_manager = RoleManager::default();
        let str = serde_json::to_string(&role_manager).unwrap();
        let a = RoleStore::init(str, contracts_db.clone());
        contracts_factory.register(
            Address::from(reserved_addresses::ROLE_MANAGEMENT),
            Box::new(a),
        );

        // register permission_contracts
        let a = PermStore::init(admin, permission_contracts, contracts_db.clone());
        contracts_factory.register(
            Address::from(reserved_addresses::PERMISSION_MANAGEMENT),
            Box::new(a),
        );

        state.borrow_mut().commit().expect("state commit error");

        trace!("**** end **** \n");
        let root = state.borrow().root;
        trace!("root {:?}", root);
        self.block.set_state_root(root);
        self.block.rehash();

        let duration = start.elapsed();
        trace!("Create genesis using times: {:?}", duration);

        self.save(state_db.database())
    }

    fn save(&mut self, db: Arc<CitaDB>) -> Result<(), String> {
        // Note: All the key should be the index from extras.rs, and
        // all the value should be a rlp value.
        let hash = self.block.hash().unwrap();

        // Insert [hash, block_header]
        let hash_key = db_indexes::Hash2Header(hash).get_index();

        // Need to get header in init function.
        db.insert(
            Some(DataCategory::Headers),
            hash_key.to_vec(),
            self.block.header().rlp(),
        )
        .expect("Insert block header error.");

        // Insert [current_hash, hash]
        let current_hash_key = db_indexes::CurrentHash.get_index();
        let hash_value = encode(&hash).to_vec();
        db.insert(
            Some(DataCategory::Extra),
            current_hash_key.to_vec(),
            hash_value.clone(),
        )
        .expect("Insert block hash error.");

        // Insert [block_number, hash]
        let height_key = db_indexes::BlockNumber2Hash(self.block.number()).get_index();

        db.insert(Some(DataCategory::Extra), height_key.to_vec(), hash_value)
            .expect("Insert block hash error.");

        Ok(())
    }
}

pub fn is_permssion_contract(addr: Address) -> bool {
    if addr == Address::from(reserved_addresses::PERMISSION_SEND_TX)
        || addr == Address::from(reserved_addresses::PERMISSION_CREATE_CONTRACT)
        || addr == Address::from(reserved_addresses::PERMISSION_NEW_PERMISSION)
        || addr == Address::from(reserved_addresses::PERMISSION_DELETE_PERMISSION)
        || addr == Address::from(reserved_addresses::PERMISSION_UPDATE_PERMISSION)
        || addr == Address::from(reserved_addresses::PERMISSION_SET_AUTH)
        || addr == Address::from(reserved_addresses::PERMISSION_CANCEL_AUTH)
        || addr == Address::from(reserved_addresses::PERMISSION_NEW_ROLE)
        || addr == Address::from(reserved_addresses::PERMISSION_DELETE_ROLE)
        || addr == Address::from(reserved_addresses::PERMISSION_UPDATE_ROLE)
        || addr == Address::from(reserved_addresses::PERMISSION_SET_ROLE)
        || addr == Address::from(reserved_addresses::PERMISSION_CANCEL_ROLE)
        || addr == Address::from(reserved_addresses::PERMISSION_NEW_GROUP)
        || addr == Address::from(reserved_addresses::PERMISSION_DELETE_GROUP)
        || addr == Address::from(reserved_addresses::PERMISSION_UPDATE_GROUP)
        || addr == Address::from(reserved_addresses::PERMISSION_NEW_NODE)
        || addr == Address::from(reserved_addresses::PERMISSION_DELETE_NODE)
        || addr == Address::from(reserved_addresses::PERMISSION_UPDATE_NODE)
        || addr == Address::from(reserved_addresses::PERMISSION_ACCOUNT_QUOTA)
        || addr == Address::from(reserved_addresses::PERMISSION_BLOCK_QUOTA)
        || addr == Address::from(reserved_addresses::PERMISSION_BATCH_TX)
        || addr == Address::from(reserved_addresses::PERMISSION_EMERGENCY_INTERVENTION)
        || addr == Address::from(reserved_addresses::PERMISSION_QUOTA_PRICE)
        || addr == Address::from(reserved_addresses::PERMISSION_VERSION)
    {
        return true;
    }
    false
}

#[cfg(test)]
mod test {
    use crate::libexecutor::genesis::{Contract, Spec};
    use cita_types::{H256, U256};
    use serde_json;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    #[test]
    fn test_spec() {
        let genesis = json!({
            "timestamp": 1524000000,
            "alloc": {
                "0xffffffffffffffffffffffffffffffffff021019": {
                    "nonce": "1",
                    "code": "0x6060604052600436106100745763",
                    "storage": {
                        "0x00": "0x013241b2",
                        "0x01": "0x02",
                    }
                },
                "0x000000000000000000000000000000000a3241b6": {
                    "nonce": "1",
                    "code": "0x6060604052600436106100745763",
                    "value": "0x10000000",
                    "storage": {}
                },
            },
            "prevhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        });
        let spec = Spec {
            prevhash: H256::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            timestamp: 1524000000,
            alloc: [
                (
                    "0xffffffffffffffffffffffffffffffffff021019".to_owned(),
                    Contract {
                        nonce: "1".to_owned(),
                        code: "0x6060604052600436106100745763".to_owned(),
                        value: None,
                        storage: [
                            ("0x00".to_owned(), "0x013241b2".to_owned()),
                            ("0x01".to_owned(), "0x02".to_owned()),
                        ]
                        .iter()
                        .cloned()
                        .collect(),
                    },
                ),
                (
                    "0x000000000000000000000000000000000a3241b6".to_owned(),
                    Contract {
                        nonce: "1".to_owned(),
                        code: "0x6060604052600436106100745763".to_owned(),
                        value: Some(U256::from(0x10000000)),
                        storage: BTreeMap::new(),
                    },
                ),
            ]
            .iter()
            .cloned()
            .collect(),
        };
        assert_eq!(serde_json::from_value::<Spec>(genesis).unwrap(), spec);
    }
}

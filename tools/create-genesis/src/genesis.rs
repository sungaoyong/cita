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

use std::collections::BTreeMap;
use std::fs::File;
use std::str::FromStr;

use crate::contracts::ContractsData;
use crate::params::InitData;
use crate::solc::Solc;

use cita_types::traits::LowerHex;
use cita_types::{clean_0x, Address, U256};
use ethabi::Token;
use serde::{Deserialize, Serialize};

pub struct GenesisCreator<'a> {
    pub contract_dir: &'a str,
    pub contract_docs_dir: &'a str,
    pub genesis_path: &'a str,
    pub timestamp: u64,
    pub init_token: &'a str,
    pub prevhash: &'a str,
    pub contract_args: InitData,
    pub contract_list: ContractsData,
    pub accounts: BTreeMap<String, Account>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub nonce: U256,
    pub code: String,
    pub storage: BTreeMap<String, String>,
    pub value: U256,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Genesis {
    pub timestamp: u64,
    pub prevhash: String,
    pub alloc: BTreeMap<String, Account>,
}

impl<'a> GenesisCreator<'a> {
    pub fn new(
        contract_dir: &'a str,
        contract_docs_dir: &'a str,
        params_path: &'a str,
        genesis_path: &'a str,
        timestamp: u64,
        init_token: &'a str,
        prevhash: &'a str,
    ) -> Self {
        let params = InitData::load_contract_args(params_path);
        let contracts_list = contract_dir.to_owned() + "/contracts.yml";
        let constracts = ContractsData::load_contract_list(&contracts_list);

        GenesisCreator {
            contract_dir,
            contract_docs_dir,
            genesis_path,
            timestamp,
            init_token,
            prevhash,
            contract_args: params,
            contract_list: constracts,
            accounts: BTreeMap::new(),
        }
    }

    pub fn create(&mut self) {
        // 1. Check compile exit or not
        if !Solc::compiler_version() {
            panic!("solc compiler not exit");
        }
        // 2. Init normal contracts
        self.init_normal_contracts();
        // 3. Init permission contracts
        self.init_permission_contracts();

        // 4. Save super admin
        let super_admin = self.contract_args.contracts.admin.admin.clone();
        self.set_account_value(
            &super_admin,
            U256::from_str(clean_0x(&self.init_token)).unwrap(),
        );
        // 5. Save genesis to file
        self.save_to_file();
        println!("Create genesis successfully !");
    }

    pub fn init_normal_contracts(&mut self) {
        let normal_params = self.contract_args.get_params();
        for (contract_name, contract_info) in self.contract_list.normal_contracts.list().iter() {
            let address = &contract_info.address;
            let params = normal_params
                .get(*contract_name)
                .map_or(Vec::new(), |p| (*p).clone());

            if *contract_name == "Admin" || *contract_name == "QuotaManager" {
                let mut param = BTreeMap::new();
                let addr = params
                    .get(0)
                    .map(|s| s.clone().to_address())
                    .unwrap()
                    .unwrap();
                param.insert("admin".to_string(), addr.lower_hex());
                let contract = Account {
                    nonce: U256::from(1),
                    code: "".to_string(),
                    storage: param,
                    value: U256::from(0),
                };
                self.accounts.insert((*address).clone(), contract);
                println!("Normal contracts: {:?} {:?} is ok!", contract_name, address);
            } else if *contract_name == "PriceManager" {
                let mut param = BTreeMap::new();
                let quota_price = params.get(0).map(|s| s.clone().to_uint()).unwrap().unwrap();
                param.insert("quota_price".to_string(), quota_price.to_string());
                let contract = Account {
                    nonce: U256::from(1),
                    code: "".to_string(),
                    storage: param,
                    value: U256::from(0),
                };
                self.accounts.insert((*address).clone(), contract);
                println!("Normal contracts: {:?} {:?} is ok!", contract_name, address);
            } else if *contract_name == "VersionManager" {
                let mut param = BTreeMap::new();
                let version = params.get(0).map(|s| s.clone().to_uint()).unwrap().unwrap();
                param.insert("version".to_string(), version.to_string());
                let contract = Account {
                    nonce: U256::from(1),
                    code: "".to_string(),
                    storage: param,
                    value: U256::from(0),
                };
                self.accounts.insert((*address).clone(), contract);
                println!("Normal contracts: {:?} {:?} is ok!", contract_name, address);
            }
            //  else if *contract_name == "Authorization" {
            //     let mut param = BTreeMap::new();
            //     let addr = params
            //         .get(0)
            //         .map(|s| s.clone().to_address())
            //         .unwrap()
            //         .unwrap();
            //     param.insert("admin".to_string(), addr.lower_hex());
            //     let contract = Account {
            //         nonce: U256::from(1),
            //         code: "".to_string(),
            //         storage: param,
            //         value: U256::from(0),
            //     };
            //     self.accounts.insert((*address).clone(), contract);
            //     println!("Normal contracts: {:?} {:?} is ok!", contract_name, address);
            // }
            else if *contract_name == "NodeManager" {
                match (params.get(0), params.get(1)) {
                    (Some(Token::Array(n)), Some(Token::Array(s))) => {
                        let nodes = n
                            .iter()
                            .map(|i| match i {
                                Token::Address(x) => Address::from_slice(x),
                                _ => unreachable!(),
                            })
                            .collect::<Vec<Address>>();

                        let stakes: Vec<U256> = s
                            .iter()
                            .map(|i| match i {
                                Token::Uint(x) => U256::from(*x),
                                _ => unreachable!(),
                            })
                            .collect::<Vec<U256>>();

                        let mut param = BTreeMap::new();
                        for i in 0..nodes.len() {
                            param.insert(nodes[i].lower_hex(), stakes[i].lower_hex());
                        }

                        let contract = Account {
                            nonce: U256::from(1),
                            code: "".to_string(),
                            storage: param,
                            value: U256::from(0),
                        };
                        self.accounts.insert((*address).clone(), contract);
                        println!("Normal contracts: {:?} {:?} is ok!", contract_name, address);
                    }
                    _ => panic!("parse error when init node manager"),
                }
            } else if *contract_name == "Group" {
                match (params.get(0), params.get(1), params.get(2)) {
                    (
                        Some(Token::Address(a)),
                        Some(Token::FixedBytes(b)),
                        Some(Token::Array(s)),
                    ) => {
                        let parent = Address::from_slice(a);
                        let name = String::from_utf8(b.to_vec()).unwrap();
                        let accounts = s
                            .iter()
                            .map(|i| match i {
                                Token::Address(x) => Address::from_slice(x),
                                _ => unreachable!(),
                            })
                            .collect::<Vec<Address>>();
                        let mut param = BTreeMap::new();
                        param.insert("parent".to_string(), parent.lower_hex());
                        param.insert("name".to_string(), name.to_string());
                        for i in 0..accounts.len() {
                            param.insert("accounts".to_string(), accounts[i].lower_hex());
                        }

                        let contract = Account {
                            nonce: U256::from(1),
                            code: "".to_string(),
                            storage: param,
                            value: U256::from(0),
                        };
                        self.accounts.insert((*address).clone(), contract);
                        println!("Normal contracts: {:?} {:?} is ok!", contract_name, address);
                    }
                    _ => panic!("parse error when init group"),
                }
            } else if *contract_name == "SysConfig" {
                let mut param = BTreeMap::new();
                let delay_block_number =
                    params.get(0).map(|s| s.clone().to_uint()).unwrap().unwrap();
                let chain_owner = params
                    .get(1)
                    .map(|s| s.clone().to_address())
                    .unwrap()
                    .unwrap();
                let chain_name = params
                    .get(2)
                    .map(|s| s.clone().to_string())
                    .unwrap()
                    .unwrap();
                let chain_id = params.get(3).map(|s| s.clone().to_uint()).unwrap().unwrap();
                let operator = params.get(4).map(|s| s.to_string()).unwrap();
                let website = params
                    .get(5)
                    .map(|s| s.clone().to_string())
                    .unwrap()
                    .unwrap();
                let block_interval = params.get(6).map(|s| s.clone().to_uint()).unwrap().unwrap();
                let economical_model = params.get(7).map(|s| s.clone().to_uint()).unwrap().unwrap();
                let name = params
                    .get(8)
                    .map(|s| s.clone().to_string())
                    .unwrap()
                    .unwrap();
                let symbol = params
                    .get(9)
                    .map(|s| s.clone().to_string())
                    .unwrap()
                    .unwrap();
                let avatar = params
                    .get(10)
                    .map(|s| s.clone().to_string())
                    .unwrap()
                    .unwrap();

                let flags = match params.get(11) {
                    Some(Token::Array(s)) => s
                        .iter()
                        .map(|i| match i {
                            Token::Bool(b) => *b,
                            _ => panic!("should not be here"),
                        })
                        .collect::<Vec<bool>>(),
                    _ => panic!("should not be here"),
                };

                param.insert(
                    "delay_block_number".to_string(),
                    delay_block_number.lower_hex(),
                );
                param.insert("chain_owner".to_string(), chain_owner.lower_hex());
                param.insert("chain_name".to_string(), chain_name.to_string());
                param.insert("chain_id".to_string(), chain_id.lower_hex());
                param.insert("operator".to_string(), operator.to_string());
                param.insert("website".to_string(), website.to_string());
                param.insert("block_interval".to_string(), block_interval.lower_hex());
                param.insert("economical_model".to_string(), economical_model.lower_hex());
                param.insert("name".to_string(), name.to_string());
                param.insert("symbol".to_string(), symbol.to_string());
                param.insert("avatar".to_string(), avatar.to_string());
                param.insert("check_call_permission".to_string(), flags[0].to_string());
                param.insert("check_send_tx_permission".to_string(), flags[1].to_string());
                param.insert(
                    "check_create_contract_permission".to_string(),
                    flags[2].to_string(),
                );
                param.insert("check_quota".to_string(), flags[3].to_string());
                param.insert("check_fee_back_platform".to_string(), flags[4].to_string());
                param.insert("auto_exec".to_string(), flags[5].to_string());

                let contract = Account {
                    nonce: U256::from(1),
                    code: "".to_string(),
                    storage: param,
                    value: U256::from(0),
                };
                self.accounts.insert((*address).clone(), contract);
                println!("Normal contracts: {:?} {:?} is ok!", contract_name, address);
            } else if *contract_name == "ChainManager"
                || *contract_name == "GroupManagement"
                || *contract_name == "AllGroups"
                || *contract_name == "EmergencyIntervention"
                || *contract_name == "AutoExec"
                || *contract_name == "BatchTx"
                || *contract_name == "RoleManagement"
                || *contract_name == "RoleCreator"
                || *contract_name == "RoleAuth"
                || *contract_name == "GroupCreator"
                || *contract_name == "Authorization"
            {
                // has constructor without parameters or no constructor
                println!("Normal contracts: {:?} {:?} is ok!", contract_name, address);
                continue;
            }
        }
    }

    pub fn init_permission_contracts(&mut self) {
        let normal_contracts = self.contract_list.normal_contracts.clone();
        let perm_contracts = self.contract_list.permission_contracts.clone();
        for (name, info) in perm_contracts.basic.list().iter() {
            let address = &info.address;
            let mut params = BTreeMap::new();
            params.insert("perm_name".to_string(), name.to_string());
            params.insert("".to_string(), info.address.clone());

            let account = Account {
                nonce: U256::from(1),
                code: "".to_string(),
                storage: params,
                value: U256::from(0),
            };
            self.accounts.insert(address.clone(), account);
            println!("Permission contracts: {:?} {:?} is ok!", name, address);
        }

        for (name, info) in perm_contracts.contracts.list().iter() {
            let address = &info.address;
            let params = self
                .contract_list
                .permission_contracts
                .contracts
                .as_params(&normal_contracts, name);
            let account = Account {
                nonce: U256::from(1),
                code: "".to_string(),
                storage: params,
                value: U256::from(0),
            };
            self.accounts.insert((*address).clone(), account);
            println!("Permission contracts: {:?} {:?} is ok!", name, address);
        }
    }

    pub fn set_account_value(&mut self, address: &str, value: U256) {
        let account = Account {
            nonce: U256::one(),
            code: String::from(""),
            storage: BTreeMap::new(),
            value,
        };
        self.accounts.insert(address.to_owned(), account);
    }

    pub fn save_to_file(&mut self) {
        let mut genesis = Genesis::default();
        genesis.timestamp = self.timestamp;
        genesis.prevhash = self.prevhash.to_owned();
        genesis.alloc = self.accounts.clone();
        let f = File::create(self.genesis_path.to_owned()).expect("failed to create genesis.json.");
        let _ = serde_json::to_writer_pretty(f, &genesis);
    }
}

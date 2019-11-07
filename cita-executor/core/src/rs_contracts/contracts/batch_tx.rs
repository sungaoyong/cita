use super::contract::Contract;
use super::utils::extract_to_u32;

use cita_types::{Address, H256, U256};
use common_types::context::Context;
use common_types::errors::ContractError;

use crate::cita_executive::{
    build_evm_context, build_vm_exec_params, call as vm_call, ExecutiveParams,
};
use crate::cita_vm_helper::get_interpreter_conf;
use crate::data_provider::Store as VMSubState;
use crate::libexecutor::block::EVMBlockDataProvider;
use crate::rs_contracts::storage::db_contracts::ContractsDB;
use cita_trie::DB;
use cita_vm::evm::{InterpreterParams, InterpreterResult};
use cita_vm::state::State;
use ethabi::param_type::ParamType;
use ethabi::Token;
use std::cell::RefCell;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct BatchTx;

impl<B: DB + 'static> Contract<B> for BatchTx {
    fn execute(
        &self,
        params: &InterpreterParams,
        context: &Context,
        contracts_db: Arc<ContractsDB>,
        state: Arc<RefCell<State<B>>>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - batch tx - enter execute");
        let result = extract_to_u32(&params.input[..]).and_then(|signature| match signature {
            0x82cc3327 => self.multi_txs(params, context, state.clone(), contracts_db.clone()),
            _ => panic!("Invalid function signature".to_owned()),
        });

        return result;
    }
}

impl BatchTx {
    pub fn multi_txs<B: DB + 'static>(
        &self,
        params: &InterpreterParams,
        context: &Context,
        state: Arc<RefCell<State<B>>>,
        contracts_db: Arc<ContractsDB>,
    ) -> Result<InterpreterResult, ContractError> {
        trace!("System contract - batch tx - multi txs");
        let input = ethabi::decode(&[ParamType::Bytes], &params.input[4..]).unwrap();

        if let Some(param) = input.get(0) {
            let bin = match param {
                Token::Bytes(s) => s,
                _ => unreachable!(),
            };

            let mut index = 0;
            let mut all_logs = Vec::new();
            while index < bin.len() {
                let code_address = Address::from(&bin[index..index + 20]);
                index = index + 20;

                let data_len = &bin[index..index + 4];
                let dl = U256::from(&data_len[..]);
                index = index + 4;

                let parameter = &bin[index..index + dl.as_usize()];
                index = index + dl.as_usize();
                trace!(
                    "Batch tx execute: code_address {:?} data_len {:?} parameter {:?}",
                    code_address,
                    dl.as_u64(),
                    parameter
                );

                // execute tx
                let params = ExecutiveParams {
                    code_address: Some(code_address),
                    sender: Address::from(0x0),
                    to_address: Some(code_address),
                    gas: U256::from(params.gas_limit),
                    gas_price: U256::from(1),
                    value: U256::from(0),
                    nonce: U256::from(0),
                    data: Some(parameter.to_vec()),
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
                    Ok(res) => {
                        trace!("res is {:?}", res);
                        match res {
                            InterpreterResult::Normal(_, _, mut logs) => {
                                trace!("logs is {:?}", logs);
                                all_logs.append(&mut logs);
                            }
                            _ => unreachable!(),
                        }
                    }
                    Err(e) => {
                        return Err(ContractError::Internal(format!(
                            "System contract execute error{}",
                            e
                        )))
                    }
                };
            }
            return Ok(InterpreterResult::Normal(
                H256::from(1).0.to_vec(),
                params.gas_limit,
                all_logs,
            ));
        }

        Err(ContractError::Internal(
            "System contract execute error".to_owned(),
        ))
    }
}

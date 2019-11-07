use cita_types::Address;
use std::cmp::Ordering;
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Permission {
    name: String,
    resources: BTreeSet<Resource>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Resource {
    addr: Address,
    func: Vec<u8>,
}

impl Ord for Resource {
    fn cmp(&self, other: &Self) -> Ordering {
        self.func.cmp(&other.func)
    }
}

impl PartialOrd for Resource {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Permission {
    pub fn new(name: String, contracts: Vec<Address>, funcs: Vec<Vec<u8>>) -> Self {
        let mut perm = Permission::default();
        perm.name = name;
        for i in 0..contracts.len() {
            let resource = Resource {
                addr: contracts[i],
                func: funcs[i].clone(),
            };
            perm.resources.insert(resource);
        }
        perm
    }

    pub fn add_resources(&mut self, contracts: Vec<Address>, funcs: Vec<Vec<u8>>) {
        for i in 0..contracts.len() {
            let resource = Resource {
                addr: contracts[i],
                func: funcs[i].clone(),
            };
            self.resources.insert(resource);
        }
    }

    pub fn delete_resources(&mut self, contracts: Vec<Address>, funcs: Vec<Vec<u8>>) {
        for i in 0..contracts.len() {
            let resource = Resource {
                addr: contracts[i],
                func: funcs[i].clone(),
            };
            self.resources.remove(&resource);
        }
    }

    pub fn update_name(&mut self, name: &str) {
        self.name = name.to_owned();
    }

    pub fn in_permission(&self, cont: Address, func: Vec<u8>) -> bool {
        let resource = Resource {
            addr: cont,
            func: func,
        };
        self.resources.contains(&resource)
    }

    pub fn query_name(&self) -> String {
        trace!("Permission name in query name is {:?}", self.name);
        self.name.clone()
    }

    pub fn query_resource(&self) -> (Vec<Address>, Vec<Vec<u8>>) {
        let mut conts = Vec::new();
        let mut funcs = Vec::new();

        for r in self.resources.iter() {
            conts.push(r.addr.clone());
            funcs.push(r.func.clone());
        }

        (conts, funcs)
    }
}

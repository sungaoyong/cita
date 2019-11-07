use cita_types::Address;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Group {
    name: String,
    parent: Address,
    accounts: Vec<Address>,
    children: Vec<Address>,
}

impl Group {
    pub fn new(name: String, parent: Address, accounts: Vec<Address>) -> Self {
        Group {
            name,
            parent,
            accounts,
            children: Vec::new(),
        }
    }

    pub fn add_accounts(&mut self, accounts: Vec<Address>) {
        for i in accounts.iter() {
            if !self.accounts.contains(i) {
                self.accounts.push(*i);
            }
        }
    }

    pub fn delete_accounts(&mut self, account: Vec<Address>) {
        for i in account.iter() {
            self.accounts.retain(|&x| x != *i);
        }
    }

    pub fn update_name(&mut self, name: &str) {
        self.name = name.to_owned();
    }

    pub fn delete_child(&mut self, child: Address) {
        self.children.retain(|&x| x != child);
    }

    pub fn add_child(&mut self, child: Address) {
        if !self.children.contains(&child) {
            self.children.push(child);
        }
    }

    pub fn query_name(&self) -> String {
        self.name.clone()
    }

    pub fn query_accounts(&self) -> Vec<Address> {
        self.accounts.clone()
    }

    pub fn query_childs(&self) -> Vec<Address> {
        self.children.clone()
    }

    pub fn query_parent(&self) -> Address {
        self.parent.clone()
    }

    pub fn query_childs_len(&self) -> usize {
        self.children.len()
    }

    pub fn in_group(&self, account: Address) -> bool {
        self.accounts.contains(&account)
    }
}

use cita_types::Address;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Role {
    name: String,
    permissions: Vec<Address>,
    accounts: Vec<Address>,
}

impl Role {
    pub fn new(name: String, permissions: Vec<Address>) -> Self {
        Role {
            name,
            permissions,
            accounts: Vec::new(),
        }
    }

    pub fn update_name(&mut self, name: &str) {
        self.name = name.to_owned();
    }

    pub fn add_permissions(&mut self, permissions: Vec<Address>) {
        for i in permissions.iter() {
            if !self.permissions.contains(i) {
                self.permissions.push(*i);
            }
        }
    }

    pub fn delete_permissions(&mut self, permissions: Vec<Address>) {
        for i in permissions.iter() {
            self.permissions.retain(|&x| x != *i);
        }
    }

    pub fn add_account(&mut self, account: Address) {
        if !self.accounts.contains(&account) {
            self.accounts.push(account);
        }
    }

    pub fn delete_account(&mut self, account: Address) {
        self.accounts.retain(|&x| x != account);
    }

    pub fn clear(&mut self) {
        self.name.clear();
        self.permissions.clear();
        self.accounts.clear();
    }
    pub fn query_role(&self) -> (String, Vec<Address>) {
        (self.name.clone(), self.permissions.clone())
    }

    pub fn query_name(&self) -> String {
        self.name.clone()
    }

    pub fn query_permssions(&self) -> Vec<Address> {
        self.permissions.clone()
    }

    pub fn query_accounts(&self) -> Vec<Address> {
        self.accounts.clone()
    }

    pub fn query_permssions_len(&self) -> usize {
        self.permissions.len()
    }

    pub fn in_permissions(&self, permission: Address) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn in_accounts(&self, account: &Address) -> bool {
        self.accounts.contains(account)
    }
}

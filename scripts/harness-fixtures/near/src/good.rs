// Idioms the lead scan must not flag.
use near_sdk::env;

#[private]
pub fn settle() -> String {
    env::predecessor_account_id().to_string()
}

#[init]
pub fn new() {}

pub fn credit(balance: u128, amount: u128) -> Option<u128> {
    balance.checked_add(amount)
}

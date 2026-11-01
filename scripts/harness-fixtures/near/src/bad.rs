// Intentionally risky snippets for the harness self-test. Not a contract.
use near_sdk::env;

pub fn auth() -> String {
    env::signer_account_id().to_string()
}

#[init(ignore_state)]
pub fn migrate() {}

pub fn pay(account: AccountId, amount: u128, opt: Option<u128>) {
    let _ = amount.wrapping_add(1);
    let _ = amount as u64;
    let _ = env::promise_result(0);
    Promise::new(account).then(other);
    let _ = opt.unwrap();
}

pub fn ft_transfer(receiver: AccountId, amount: U128) {}

pub fn ft_on_transfer(sender: AccountId, amount: U128) -> U128 {
    amount
}

pub fn ft_resolve_transfer(sender: AccountId, amount: U128) -> U128 {
    amount
}

pub fn draw() -> Vec<u8> {
    env::random_seed()
}

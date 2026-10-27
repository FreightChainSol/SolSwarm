// Intentionally vulnerable snippets for the harness self-test. Not a program.
pub struct Raw<'info> {
    pub vault: UncheckedAccount<'info>,
    pub user: AccountInfo<'info>,
}

pub fn reinit() {
    let _ = init_if_needed;
}

pub fn bump(program_id: &Pubkey, bump: u8) {
    let _ = create_program_address(&[b"vault", &[bump]], program_id);
}

pub fn cpi(accounts: &[AccountInfo]) {
    invoke(&ix, accounts)?;
    let _ = accounts.remaining_accounts;
}

pub fn decode(data: &[u8]) {
    let _ = Account::try_from_slice(data);
    load_instruction_at(0, data)?;
}

#[account(mut, close = authority)]
pub struct Gone {}

pub fn take(vault: &AccountInfo) {
    **vault.try_borrow_mut_lamports()? -= 1;
    **vault.lamports.borrow_mut() = 0;
    let _ = CpiContext::new_with_signer(program, accounts, seeds);
}

pub fn sloppy(opt: Option<u64>, amount: u64) {
    token::transfer(ctx, amount)?;
    let _ = amount.wrapping_add(1);
    let _ = amount as u32;
    let _ = opt.unwrap();
    system_program::transfer(cpi, amount)?;
    let _ = Clock::get()?.unix_timestamp;
    set_authority(ctx, AuthorityType::AccountOwner, None)?;
}

#[account(mut, realloc = 100, realloc::payer = payer, realloc::zero = false)]
pub struct Grow {}

/// CHECK: supplied by the caller
pub struct Loose {}

// Idioms the lead scan must not flag.
pub struct Safe<'info> {
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub row: Account<'info, Row>,
}

pub fn canonical(program_id: &Pubkey) {
    let (_pda, _bump) = find_program_address(&[b"vault", user.key().as_ref()], program_id);
}

pub fn introspect(data: &[u8]) {
    let _ = load_instruction_at_checked(0, data);
}

pub fn pay(balance: u64) {
    let _ = CpiContext::new(program, accounts);
    let _next = balance.checked_add(1);
}

pub fn careful(amount: u64) -> Result<()> {
    token_interface::transfer_checked(ctx, amount, decimals)?;
    let _ = amount.checked_mul(2).ok_or(ErrorCode::Overflow)?;
    let _ = u32::try_from(amount)?;
    Ok(())
}

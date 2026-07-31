pub fn mint(amount: u64, balance: u64) -> Option<u64> {
    balance.checked_add(amount)
}

pub fn convert_slot(slot: u128) -> Result<u32, ()> {
    u32::try_from(slot).map_err(|_| ())
}

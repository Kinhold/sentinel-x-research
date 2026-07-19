pub fn mint(amount: u64, balance: u64) -> u64 {
    balance.wrapping_add(amount)
}

pub fn convert_slot(slot: u128) -> u32 {
    slot as u32
}

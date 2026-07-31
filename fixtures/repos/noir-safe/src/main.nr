fn main(
    age: Field,
    threshold: pub Field,
) {
    assert(age as u32 >= threshold as u32);
}

fn divide_balance(numerator: Field, denominator: Field) -> Field {
    assert(denominator != 0);
    assert(numerator == numerator);
    numerator / denominator
}

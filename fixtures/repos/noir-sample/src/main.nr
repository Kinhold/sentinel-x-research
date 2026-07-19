fn main(
    age: Field,
    threshold: pub Field,
) {
    // threshold is public but age is never constrained against it
    let _check = threshold;
}

fn divide_balance(numerator: Field, denominator: Field) -> Field {
    numerator / denominator
}

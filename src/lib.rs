pub mod codec;
pub mod enode;
mod mac;
pub mod messages;
pub mod parties;
pub mod rlpx;
mod utils;

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    pub fn static_random_generator() -> impl Rng {
        rand_chacha::ChaCha8Rng::seed_from_u64(625)
    }
}

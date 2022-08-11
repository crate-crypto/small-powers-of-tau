use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use small_powers_of_tau::{keypair::PrivateKey, serialisation::SubgroupCheck, srs::Accumulator};

fn update_algo() {
    use small_powers_of_tau::srs::*;

    let params = Parameters {
        num_g1_elements_needed: 2usize.pow(16),
        num_g2_elements_needed: 16,
    };

    // Simulate deserialisation
    let acc = SRS::new(params);
    let bytes = acc.serialise();
    let mut acc = SRS::deserialise(&bytes, params, SubgroupCheck::Partial);

    let mut rng = &mut thread_rng();
    let priv_key = PrivateKey::rand(rng);
    acc.update(priv_key);
    let bytes = acc.serialise();
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("update algo", |b| b.iter(|| black_box(update_algo())));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

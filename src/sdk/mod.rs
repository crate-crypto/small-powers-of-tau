use crate::srs::Parameters;

pub mod transcript;
pub mod contribution;


pub const NUM_CEREMONIES: usize = 4;

pub const CEREMONIES: [Parameters; NUM_CEREMONIES] = [
    Parameters {
        num_g1_elements_needed: 4096,
        num_g2_elements_needed: 65,
    },
    Parameters {
        num_g1_elements_needed: 8192,
        num_g2_elements_needed: 65,
    },
    Parameters {
        num_g1_elements_needed: 16384,
        num_g2_elements_needed: 65,
    },
    Parameters {
        num_g1_elements_needed: 32768,
        num_g2_elements_needed: 65,
    },
];
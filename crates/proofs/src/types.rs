use std::str::FromStr;

use alloy_primitives::Address;

pub enum BlobstreamChainIds {
    // Mainnets
    EthereumMainnet = 1,
    ArbitrumOne = 42161,
    Base = 8453,

    // Testnets
    Sepolia = 11155111,
    ArbitrumSepolia = 421614,
    BaseSepolia = 84532,
}

impl BlobstreamChainIds {
    pub fn from_u64(id: u64) -> Option<Self> {
        match id {
            1 => Some(Self::EthereumMainnet),
            42161 => Some(Self::ArbitrumOne),
            8453 => Some(Self::Base),
            11155111 => Some(Self::Sepolia),
            421614 => Some(Self::ArbitrumSepolia),
            84532 => Some(Self::BaseSepolia),
            _ => None,
        }
    }

    pub fn blostream_address(&self) -> Address {
        match self {
            Self::EthereumMainnet => {
                Address::from_str("0x7Cf3876F681Dbb6EdA8f6FfC45D66B996Df08fAe").unwrap()
            }
            Self::ArbitrumOne => {
                Address::from_str("0xA83ca7775Bc2889825BcDeDfFa5b758cf69e8794").unwrap()
            }
            Self::Base => Address::from_str("0xA83ca7775Bc2889825BcDeDfFa5b758cf69e8794").unwrap(),
            Self::Sepolia => {
                Address::from_str("0xF0c6429ebAB2e7DC6e05DaFB61128bE21f13cb1e").unwrap()
            }
            Self::ArbitrumSepolia => {
                Address::from_str("0xc3e209eb245Fd59c8586777b499d6A665DF3ABD2").unwrap()
            }
            Self::BaseSepolia => {
                Address::from_str("0xc3e209eb245Fd59c8586777b499d6A665DF3ABD2").unwrap()
            }
        }
    }
}

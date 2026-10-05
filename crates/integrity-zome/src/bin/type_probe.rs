use hdi::prelude::*;

fn main() {
    let _author: AgentPubKey;

    let _filter = ChainFilter::new(ActionHash::from_raw_36(vec![0u8; 36]));

    let _input = MustGetAgentActivityInput {
        author: AgentPubKey::from_raw_39(vec![0u8; 39]),
        chain_filter: _filter,
    };
}

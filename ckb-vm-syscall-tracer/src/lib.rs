pub mod generated {
    pub mod traces {
        include!(concat!(env!("OUT_DIR"), "/generated.traces.rs"));
    }
}

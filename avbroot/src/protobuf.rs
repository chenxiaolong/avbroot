pub mod build {
    pub mod tools {
        pub mod releasetools {
            include!(concat!(env!("OUT_DIR"), "/build.tools.releasetools.rs"));
        }
    }
}

pub mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

fn main() -> std::io::Result<()> {
    prost_build::compile_protos(&["protos/traces.proto"], &["protos/"])?;
    Ok(())
}

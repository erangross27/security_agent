fn main() {
    // Tell Cargo to re-run this script if the manifest changes
    println!("cargo:rerun-if-changed=Cargo.toml");
    
    // Windows-specific build configurations
    #[cfg(target_os = "windows")]
    {
        // Create the manifest for UAC elevation (run as administrator)
        let manifest = r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
        "#;
        
        std::fs::write("security_agent.manifest", manifest)
            .expect("Failed to write manifest file");
        
        // Tell Cargo where to find the manifest
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:security_agent.manifest");
    }
}
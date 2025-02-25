fn main() {
    // Tell Cargo to re-run this script if the manifest changes
    println!("cargo:rerun-if-changed=Cargo.toml");
    
    // Windows-specific build configurations
    #[cfg(target_os = "windows")]
    {
        // Create a more complete manifest with explicit version info
        // This helps avoid conflicts with other embedded manifests
        let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    type="win32"
    name="SecurityAgent"
    version="1.0.0.0"
    processorArchitecture="*"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 and 11 -->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>"#;
        
        // Write the manifest to a file
        std::fs::write("security_agent.manifest", manifest)
            .expect("Failed to write manifest file");
        
        // Set linker arguments to use our manifest
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:security_agent.manifest");
    }
}
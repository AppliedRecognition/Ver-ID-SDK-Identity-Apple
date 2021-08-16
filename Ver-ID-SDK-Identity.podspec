Pod::Spec.new do |spec|

  spec.name = "Ver-ID-SDK-Identity"
  spec.version = "3.0.2"
  spec.summary = "Provides identity for clients of Ver-ID face recognition SDK"
  spec.module_name = "VerIDSDKIdentity"
  spec.homepage = "https://github.com/AppliedRecognition/"
  spec.documentation_url = "https://appliedrecognition.github.io/Ver-ID-SDK-Identity-Apple"
  spec.license = { :type => "MIT", :file => "LICENSE" }
  spec.author = "Jakub Dolejs"
  spec.swift_versions = "5.0"
  spec.ios.deployment_target = "10.0"
  spec.osx.deployment_target = "10.13.0"
  spec.source = { :git => "https://github.com/AppliedRecognition/Ver-ID-SDK-Identity-Apple.git", :tag => "v#{spec.version}" }
  spec.source_files = "VerIDSDKIdentity/*.swift"
  spec.frameworks = "Security", "SystemConfiguration"
  spec.test_spec do|test|
    test.source_files = "VerIDSDKIdentityTests/*.swift"
    test.resources = "VerIDSDKIdentityTests/*.p12"
  end

end

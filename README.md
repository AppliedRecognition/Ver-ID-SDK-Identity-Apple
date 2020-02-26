![Cocoapods platforms](https://img.shields.io/cocoapods/p/Ver-ID-SDK-Identity) ![Cocoapods](https://img.shields.io/cocoapods/v/Ver-ID-SDK-Identity) ![CI](https://github.com/AppliedRecognition/Ver-ID-SDK-Identity-Apple/workflows/CI/badge.svg?event=push)

#  Ver-ID SDK Identity

### Framework that provides a client identity to [Ver-ID SDK](https://github.com/AppliedRecognition/Ver-ID-UI-iOS) 1.11.0 and newer

## Installation

 1. Download [CocoaPods](https://cocoapods.org)
 2. Add the **Ver-ID-SDK-Identity** pod to your [Podfile](https://guides.cocoapods.org/syntax/podfile.html):
 
    ~~~ruby
    pod 'Ver-ID-SDK-Identity', '~> 1.0'
    ~~~
3. In Terminal enter `pod install` and press _enter_.

## Obtaining credentials Ver-ID SDK credentials

1. [Register your app](https://dev.ver-id.com/licensing/). You will need your app's bundle identifier.
2. Registering your app will generate an evaluation licence for your app. The licence is valid for 30 days. If you need a production licence please [contact Applied Recognition](mailto:sales@appliedrec.com).
3. When you finish the registration you'll receive a file called **Ver-ID identity.p12** and a password.

## Creating a Ver-ID SDK identity

### Option 1
1. Copy the **Ver-ID identity.p12** file in your Xcode project and include it in your app's target.
2. Place your password in your app's **Info.plist**:

    ~~~xml
    <key>com.appliedrec.verid.password</key>
    <string>your password goes here</string>
    ~~~
3. Create an instance of **VerIDSDKIdentity**:

    ~~~swift
    import VerIDSDKIdentity
    
    do {
        let identity = try VerIDSDKIdentity(url: nil, password: nil)
    } catch {
    }
    ~~~
    
### Option 2
1. Copy the **Ver-ID identity.p12** file in your Xcode project and include it in your app's target.
2. Create an instance of **VerIDSDKIdentity**:

    ~~~swift
    import VerIDSDKIdentity
    
    do {
        let identity = try VerIDSDKIdentity(password: "your password goes here")
    } catch {
    }
    ~~~
    
### Option 3
1. Upload the **Ver-ID identity.p12** online or store it in your app.
2. Create an instance of **VerIDSDKIdentity** referencing the URL of the **Ver-ID identity.p12** file:

    ~~~swift
    import VerIDSDKIdentity
    
    do {
        guard let url = URL(string: "https://ver-id.s3.us-east-1.amazonaws.com/ios/com.appliedrec.verid.licenceclient/test_assets/Ver-ID%20identity.p12") else {
            return
        }
        let identity = try VerIDSDKIdentity(url: url, password: "your password goes here")
    } catch {
    }
    ~~~
    
### Option 4
1. Upload the **Ver-ID identity.p12** online or store it in your app.
2. Place your password in your app's **Info.plist**:

    ~~~xml
    <key>com.appliedrec.verid.password</key>
    <string>your password goes here</string>
    ~~~
3. Create an instance of **VerIDSDKIdentity** referencing the URL of the **Ver-ID identity.p12** file:

    ~~~swift
    import VerIDSDKIdentity
    
    do {
        guard let url = URL(string: "https://ver-id.s3.us-east-1.amazonaws.com/ios/com.appliedrec.verid.licenceclient/test_assets/Ver-ID%20identity.p12") else {
            return
        }
        let identity = try VerIDSDKIdentity(url: url)
    } catch {
    }
    ~~~

### Option 5
1. Create your own instance of [SecIdentity](https://developer.apple.com/documentation/security/secidentity).
2. Pass the identity to the **VerIDSDKIdentity** initializer:

    ~~~swift
    import Security
    import VerIDSDKIdentity
    
    lazy var secIdentity: SecIdentity = {
        // Construct your SecIdentity instance
        let identity: SecIdentity // Stub
        return identity
    }()
    
    do {
        let identity = try VerIDSDKIdentity(identity: self.secIdentity)
    } catch {
    }
    ~~~

## Providing your identity to Ver-ID SDK 1.11.0 and newer
[Create an instance](#creating-a-ver-id-sdk-identity) of **VerIDSDKIdentity** and pass it to [**VerIDFactory**](https://appliedrecognition.github.io/Ver-ID-Core-Apple/Classes/VerIDFactory.html):

~~~swift
import VerIDSDKIdentity
import VerIDCore
    
do {
    // See above
    let identity = try VerIDSDKIdentity()
    // Construct VerIDFactory with your identity
    let veridFactory = VerIDFactory(identity: identity)
    // ... use veridFactory to create an instance of VerID
} catch {
}
~~~

## [Reference documentation](https://appliedrecognition.github.io/Ver-ID-SDK-Identity-Apple/)

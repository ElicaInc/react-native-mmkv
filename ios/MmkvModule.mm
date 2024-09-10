// Add Auto Keychain Protection
#import <Security/Security.h> // Keychain access

#import "MmkvModule.h"
#import "JSIUtils.h"

#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import <jsi/jsi.h>

#import "../cpp/TypedArray.h"
#import "MmkvHostObject.h"
#import <MMKV/MMKV.h>

using namespace facebook;

@implementation MmkvModule
NSString *encryptionKeyAuto = nil; // Added for Keychain encryption key

@synthesize bridge=_bridge;

RCT_EXPORT_MODULE(MMKV)

/* Keychain related methods - start */

- (NSString *)generateEncryptionKey {
    // Implement your logic here to generate a secure encryption key
    // You can use a library like CommonCrypto to generate a random key
    // For example, generating a 256-bit key:
    uint8_t keyBytes[32];
    int result = SecRandomCopyBytes(kSecRandomDefault, sizeof(keyBytes), keyBytes);
    if (result == errSecSuccess) {
        NSData *keyData = [NSData dataWithBytes:keyBytes length:sizeof(keyBytes)];
        return [keyData base64EncodedStringWithOptions:0];
    } else {
        // Handle key generation failure
        return nil;
    }
}

- (NSString *)getEncryptionKeyFromKeychain {
    // Retrieve the encryption key from the Keychain
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"CtcaeProService", // Replace with a unique service name
        (__bridge id)kSecReturnData: @(YES),
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
  
    CFDataRef keyData = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&keyData);
  
    if (status == errSecSuccess && keyData != NULL) {
        NSData *key = (__bridge_transfer NSData *)keyData;
        return [[NSString alloc] initWithData:key encoding:NSUTF8StringEncoding];
    } else {
        // Key not found or retrieval failed
        return nil;
    }
}

- (void)storeEncryptionKeyInKeychain:(NSString *)key {
    // Store the encryption key in the Keychain for secure storage
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"CtcaeProService", // Replace with a unique service name
        (__bridge id)kSecValueData: [key dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlocked,
        // You may want to add additional attributes for security
    };

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
    if (status != errSecSuccess && status != errSecDuplicateItem) {
        // Handle Keychain storage failure
        NSLog(@"Keychain storage error: %d", (int)status);
    }
}

- (void)deleteFromKeychain:(NSString *)key {
    // Create a query to delete the Keychain item
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"CtcaeProService", // Replace with the service name used during storage
        (__bridge id)kSecAttrAccount: key // The key you want to delete
    };

    // Delete the Keychain item
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

    if (status != errSecSuccess) {
        NSLog(@"Failed to delete Keychain item for key: %@, error: %d", key, (int)status);
    }
}

/* Keychain related methods - end */

- (void)setBridge:(RCTBridge *)bridge {
  _bridge = bridge;
}

+ (NSString*)getPropertyAsStringOrNilFromObject:(jsi::Object&)object
                                   propertyName:(std::string)propertyName
                                        runtime:(jsi::Runtime&)runtime {
  jsi::Value value = object.getProperty(runtime, propertyName.c_str());
  std::string string = value.isString() ? value.asString(runtime).utf8(runtime) : "";
  return string.length() > 0 ? [NSString stringWithUTF8String:string.c_str()] : nil;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(install : (nullable NSString*)storageDirectory) {
  NSLog(@"Installing global.mmkvCreateNewInstance...");
  RCTCxxBridge* cxxBridge = (RCTCxxBridge*)_bridge;
  if (cxxBridge == nil) {
    return @false;
  }

  using namespace facebook;

  auto jsiRuntime = (jsi::Runtime*)cxxBridge.runtime;
  if (jsiRuntime == nil) {
    return @false;
  }
  auto& runtime = *jsiRuntime;

#if DEBUG
    MMKVLogLevel logLevel = MMKVLogDebug; 
#else
    MMKVLogLevel logLevel = MMKVLogError;
#endif

  RCTUnsafeExecuteOnMainQueueSync(^{
    // Get appGroup value from info.plist using key "AppGroup"
    NSString* appGroup = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"AppGroup"];
    if (appGroup == nil) {
      [MMKV initializeMMKV:storageDirectory logLevel:logLevel];
    } else {
      NSString* groupDir = [[NSFileManager defaultManager]
                               containerURLForSecurityApplicationGroupIdentifier:appGroup]
                               .path;
      [MMKV initializeMMKV:nil groupDir:groupDir logLevel:logLevel];
    }
  });
    
    // Check if an encryption key already exists in the Keychain
    NSString *existingEncryptionKey = [self getEncryptionKeyFromKeychain];

    if (existingEncryptionKey == nil) {
        // Generate a new encryption key if it doesn't exist
        encryptionKeyAuto = [self generateEncryptionKey];

        // Store the new encryption key in the Keychain
        [self storeEncryptionKeyInKeychain:encryptionKeyAuto];
    } else {
        // Use the existing encryption key
        encryptionKeyAuto = existingEncryptionKey;
    }

  // MMKV.createNewInstance()
  auto mmkvCreateNewInstance = jsi::Function::createFromHostFunction(
      runtime, jsi::PropNameID::forAscii(runtime, "mmkvCreateNewInstance"), 1,
      [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments,
         size_t count) -> jsi::Value {
        if (count != 1) {
          throw jsi::JSError(runtime, "MMKV.createNewInstance(..) expects one argument (object)!");
        }
        jsi::Object config = arguments[0].asObject(runtime);

        NSString* instanceId = [MmkvModule getPropertyAsStringOrNilFromObject:config
                                                                 propertyName:"id"
                                                                      runtime:runtime];
        NSString* path = [MmkvModule getPropertyAsStringOrNilFromObject:config
                                                           propertyName:"path"
                                                                runtime:runtime];
        /*                                                         
        NSString* encryptionKey = [MmkvModule getPropertyAsStringOrNilFromObject:config
                                                            propertyName:"encryptionKey"
                                                                 runtime:runtime];
        */
        NSString* encryptionKey = encryptionKeyAuto; // Use the Keychain encryption key

        auto instance = std::make_shared<MmkvHostObject>(instanceId, path, encryptionKey);
        return jsi::Object::createFromHostObject(runtime, instance);
      });
  runtime.global().setProperty(runtime, "mmkvCreateNewInstance", std::move(mmkvCreateNewInstance));

  // Adds the PropNameIDCache object to the Runtime. If the Runtime gets destroyed, the Object gets
  // destroyed and the cache gets invalidated.
  auto propNameIdCache = std::make_shared<InvalidateCacheOnDestroy>(runtime);
  runtime.global().setProperty(runtime, "mmkvArrayBufferPropNameIdCache",
                               jsi::Object::createFromHostObject(runtime, propNameIdCache));

  NSLog(@"Installed global.mmkvCreateNewInstance!");
  return @true;
}

@end

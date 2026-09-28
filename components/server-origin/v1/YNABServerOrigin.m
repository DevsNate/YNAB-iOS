#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/message.h>
#import <objc/runtime.h>

#ifndef YN_BUTTON_TEMPLATE_VM_ADDRESS
#error "YN_BUTTON_TEMPLATE_VM_ADDRESS is required"
#endif
#ifndef YN_FORGOT_TITLE_OBJECT_VM_ADDRESS
#error "YN_FORGOT_TITLE_OBJECT_VM_ADDRESS is required"
#endif
#ifndef YN_FORGOT_ACCESSIBILITY_OBJECT_VM_ADDRESS
#error "YN_FORGOT_ACCESSIBILITY_OBJECT_VM_ADDRESS is required"
#endif
#ifndef YN_FORGOT_TITLE_COUNT_AND_FLAGS
#error "YN_FORGOT_TITLE_COUNT_AND_FLAGS is required"
#endif
#ifndef YN_FORGOT_ACCESSIBILITY_COUNT_AND_FLAGS
#error "YN_FORGOT_ACCESSIBILITY_COUNT_AND_FLAGS is required"
#endif
#ifndef YN_NATIVE_TEXT_ACTION_CLASS_SUFFIX
#error "YN_NATIVE_TEXT_ACTION_CLASS_SUFFIX is required"
#endif

static NSString *const YNOriginDefaultsKey = @"YNABPrivateServerOrigin";
static NSString *const YNInstallTokenDefaultsKey =
    @"YNABPrivateServerInstallToken";
static NSString *const YNOriginInstallTokenDefaultsKey =
    @"YNABPrivateServerOriginInstallToken";
static NSString *const YNStockServerInfoKey = @"YB_APP_SERVER";
static NSString *const YNUnconfiguredScheme =
    @"ynab-private-server-unconfigured";
static NSString *const YNPrimaryHost = @"app.ynab.com";
static NSString *const YNSecondaryHost = @"app.youneedabudget.com";
static const void *YNSignInButtonKey = &YNSignInButtonKey;
static const void *YNCreateAccountButtonKey = &YNCreateAccountButtonKey;
static const void *YNArrangedSubviewObserverKey = &YNArrangedSubviewObserverKey;
static const void *YNOriginPreflightTaskKey = &YNOriginPreflightTaskKey;
static const void *YNOriginPreflightTokenKey = &YNOriginPreflightTokenKey;
static const void *YNOriginPreflightOriginKey = &YNOriginPreflightOriginKey;
static NSString *const YNNativeTextActionClassSuffix =
    @YN_NATIVE_TEXT_ACTION_CLASS_SUFFIX;

static void (*YNOriginalSignInViewDidLoad)(id, SEL);
static void (*YNOriginalCreateAccountViewDidLoad)(id, SEL);
static void (*YNOriginalAddArrangedSubview)(id, SEL, UIView *);
static BOOL (*YNOriginalShouldSkipSubscribeFlow)(id, SEL);
static id (*YNOriginalBundleObjectForInfoDictionaryKey)(id, SEL, NSString *);

static NSURLSessionDataTask *(*YNOriginalDataTaskWithRequest)(id, SEL, NSURLRequest *);
static NSURLSessionDataTask *(*YNOriginalDataTaskWithRequestCompletion)(
    id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
static NSURLSessionDataTask *(*YNOriginalDataTaskWithURL)(id, SEL, NSURL *);
static NSURLSessionDataTask *(*YNOriginalDataTaskWithURLCompletion)(
    id, SEL, NSURL *, void (^)(NSData *, NSURLResponse *, NSError *));
static NSURLSessionUploadTask *(*YNOriginalUploadTaskWithData)(
    id, SEL, NSURLRequest *, NSData *);
static NSURLSessionUploadTask *(*YNOriginalUploadTaskWithDataCompletion)(
    id, SEL, NSURLRequest *, NSData *, void (^)(NSData *, NSURLResponse *, NSError *));
static NSURLSessionUploadTask *(*YNOriginalUploadTaskWithFile)(
    id, SEL, NSURLRequest *, NSURL *);
static NSURLSessionUploadTask *(*YNOriginalUploadTaskWithFileCompletion)(
    id, SEL, NSURLRequest *, NSURL *, void (^)(NSData *, NSURLResponse *, NSError *));
static NSURLSessionDownloadTask *(*YNOriginalDownloadTaskWithRequest)(
    id, SEL, NSURLRequest *);
static NSURLSessionDownloadTask *(*YNOriginalDownloadTaskWithRequestCompletion)(
    id, SEL, NSURLRequest *, void (^)(NSURL *, NSURLResponse *, NSError *));
static NSURLSessionDownloadTask *(*YNOriginalDownloadTaskWithURL)(id, SEL, NSURL *);
static NSURLSessionDownloadTask *(*YNOriginalDownloadTaskWithURLCompletion)(
    id, SEL, NSURL *, void (^)(NSURL *, NSURLResponse *, NSError *));

typedef CFTypeRef (*YNSecTaskCreateFromSelfFunction)(CFAllocatorRef);
typedef CFTypeRef (*YNSecTaskCopyValueForEntitlementFunction)(
    CFTypeRef, CFStringRef, CFErrorRef *);

typedef UIButton *(*YNButtonTemplateFactory)(
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, void *, void *);

static BOOL YNMainExecutableSlide(intptr_t *result) {
  static intptr_t slide;
  static BOOL found;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t index = 0; index < imageCount; index++) {
      const struct mach_header *header = _dyld_get_image_header(index);
      if (header && header->filetype == MH_EXECUTE) {
        slide = _dyld_get_image_vmaddr_slide(index);
        found = YES;
        break;
      }
    }
  });
  if (found && result) *result = slide;
  return found;
}

static uintptr_t YNRuntimeAddress(uint64_t vmAddress) {
  intptr_t slide = 0;
  if (!YNMainExecutableSlide(&slide)) return 0;
  return (uintptr_t)((intptr_t)vmAddress + slide);
}

static uint64_t YNImmortalStringReference(uint64_t objectVmAddress) {
  uintptr_t address = YNRuntimeAddress(objectVmAddress);
  return address ? UINT64_C(0x8000000000000000) | (uint64_t)address : 0;
}

static Class YNClass(NSString *qualifiedName, NSString *mangledName) {
  Class cls = NSClassFromString(qualifiedName);
  return cls ?: NSClassFromString(mangledName);
}

static NSString *YNCurrentAppGroup(void) {
  static NSString *group;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    void *security = dlopen(
        "/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (!security) return;
    YNSecTaskCreateFromSelfFunction createTask =
        (YNSecTaskCreateFromSelfFunction)dlsym(security, "SecTaskCreateFromSelf");
    YNSecTaskCopyValueForEntitlementFunction copyEntitlement =
        (YNSecTaskCopyValueForEntitlementFunction)dlsym(
            security, "SecTaskCopyValueForEntitlement");
    if (!createTask || !copyEntitlement) return;

    CFTypeRef task = createTask(kCFAllocatorDefault);
    if (!task) return;
    CFTypeRef value = copyEntitlement(
        task, CFSTR("com.apple.security.application-groups"), NULL);
    CFRelease(task);
    if (![(__bridge id)value isKindOfClass:NSArray.class]) {
      if (value) CFRelease(value);
      return;
    }

    NSMutableArray<NSString *> *groups = [NSMutableArray array];
    for (id candidate in (__bridge NSArray *)value) {
      if ([candidate isKindOfClass:NSString.class] && [candidate length] > 0) {
        [groups addObject:candidate];
      }
    }
    CFRelease(value);
    [groups sortUsingSelector:@selector(compare:)];
    group = groups.firstObject.copy;
  });
  return group;
}

static NSUserDefaults *YNSharedDefaults(void) {
  static NSUserDefaults *defaults;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    NSString *group = YNCurrentAppGroup();
    if (group.length > 0) defaults = [[NSUserDefaults alloc] initWithSuiteName:group];
  });
  return defaults;
}

static BOOL YNIsMainApplicationProcess(void) {
  return [NSBundle.mainBundle.bundleURL.pathExtension.lowercaseString
      isEqualToString:@"app"];
}

static NSString *YNCurrentInstallToken(void) {
  if (!YNIsMainApplicationProcess()) return nil;
  NSUserDefaults *local = NSUserDefaults.standardUserDefaults;
  NSString *token = [local stringForKey:YNInstallTokenDefaultsKey];
  if (token.length == 0) {
    token = NSUUID.UUID.UUIDString;
    [local setObject:token forKey:YNInstallTokenDefaultsKey];
  }
  return token;
}

static void YNReconcileOriginOwnership(void) {
  if (!YNIsMainApplicationProcess()) return;
  NSUserDefaults *shared = YNSharedDefaults();
  NSString *origin = [shared stringForKey:YNOriginDefaultsKey];
  if (origin.length == 0) return;
  NSString *currentToken = YNCurrentInstallToken();
  NSString *ownerToken =
      [shared stringForKey:YNOriginInstallTokenDefaultsKey];
  if (currentToken.length > 0 && [ownerToken isEqualToString:currentToken]) {
    return;
  }
  // App Group preferences can outlive an app-container uninstall. Bind the
  // selected origin to this installation so a genuine reinstall cannot
  // silently inherit and preflight an obsolete private-server address. The
  // main container and its token survive an ordinary in-place upgrade.
  [shared removeObjectForKey:YNOriginDefaultsKey];
  [shared removeObjectForKey:YNOriginInstallTokenDefaultsKey];
}

static BOOL YNIsPrivateIPv4(NSString *host) {
  struct in_addr address;
  if (inet_pton(AF_INET, host.UTF8String, &address) != 1) return NO;
  uint32_t value = ntohl(address.s_addr);
  uint8_t first = (uint8_t)(value >> 24);
  uint8_t second = (uint8_t)(value >> 16);
  return first == 10 || first == 127 ||
         (first == 172 && second >= 16 && second <= 31) ||
         (first == 192 && second == 168) ||
         (first == 169 && second == 254);
}

static BOOL YNIsPrivateIPv6(NSString *host) {
  struct in6_addr address;
  if (inet_pton(AF_INET6, host.UTF8String, &address) != 1) return NO;
  const uint8_t *bytes = address.s6_addr;
  static const uint8_t loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 1};
  return memcmp(bytes, loopback, sizeof(loopback)) == 0 ||
         (bytes[0] & 0xFE) == 0xFC ||
         (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80);
}

static BOOL YNIsPrivateDevelopmentHost(NSString *host) {
  NSString *lower = host.lowercaseString;
  return [lower isEqualToString:@"localhost"] ||
         [lower hasSuffix:@".local"] ||
         YNIsPrivateIPv4(lower) || YNIsPrivateIPv6(lower);
}

static NSString *YNNormalizeOrigin(NSString *value) {
  if (![value isKindOfClass:NSString.class]) return nil;
  NSString *trimmed = [value stringByTrimmingCharactersInSet:
      NSCharacterSet.whitespaceAndNewlineCharacterSet];
  if (trimmed.length == 0) return nil;

  NSURLComponents *components = [NSURLComponents componentsWithString:trimmed];
  NSString *scheme = components.scheme.lowercaseString;
  NSString *host = components.host.lowercaseString;
  if (host.length == 0 ||
      (![scheme isEqualToString:@"https"] && ![scheme isEqualToString:@"http"])) {
    return nil;
  }
  if ([scheme isEqualToString:@"http"] && !YNIsPrivateDevelopmentHost(host)) {
    return nil;
  }
  if (components.user.length || components.password.length ||
      components.query.length || components.fragment.length) {
    return nil;
  }
  if (components.path.length && ![components.path isEqualToString:@"/"]) return nil;
  if (components.port &&
      (components.port.integerValue < 1 || components.port.integerValue > 65535)) {
    return nil;
  }

  components.scheme = scheme;
  components.host = host;
  components.path = @"";
  NSURL *url = components.URL;
  return url.absoluteString;
}

static NSString *YNStoredOrigin(void) {
  return YNNormalizeOrigin([YNSharedDefaults() stringForKey:YNOriginDefaultsKey]);
}

static NSURL *YNHealthURL(NSString *origin) {
  NSURLComponents *components = [NSURLComponents componentsWithString:origin];
  if (!components || components.host.length == 0) return nil;
  components.path = @"/health";
  components.query = nil;
  components.fragment = nil;
  return components.URL;
}

static BOOL YNIsOwnedHost(NSString *host) {
  NSString *lower = host.lowercaseString;
  return [lower isEqualToString:YNPrimaryHost] ||
         [lower isEqualToString:YNSecondaryHost];
}

static NSURL *YNBlockedOwnedURL(NSURL *stockURL) {
  NSURLComponents *blocked = [NSURLComponents componentsWithURL:stockURL
                                          resolvingAgainstBaseURL:NO];
  blocked.scheme = YNUnconfiguredScheme;
  blocked.host = @"not-configured";
  blocked.port = nil;
  return blocked.URL ?: [NSURL URLWithString:
      @"ynab-private-server-unconfigured://not-configured/"];
}

static NSURL *YNRewriteURL(NSURL *stockURL) {
  if (!stockURL || !YNIsOwnedHost(stockURL.host)) return stockURL;
  NSString *originString = YNStoredOrigin();
  if (!originString) return YNBlockedOwnedURL(stockURL);

  NSURLComponents *origin = [NSURLComponents componentsWithString:originString];
  NSURLComponents *target = [NSURLComponents componentsWithURL:stockURL
                                        resolvingAgainstBaseURL:NO];
  if (!origin || !target || origin.scheme.length == 0 || origin.host.length == 0) {
    return stockURL;
  }
  target.scheme = origin.scheme;
  target.host = origin.host;
  target.port = origin.port;
  return target.URL ?: stockURL;
}

static id YNBundleObjectForInfoDictionaryKey(
    id self, SEL selector, NSString *key) {
  if ([key isEqualToString:YNStockServerInfoKey] &&
      self == NSBundle.mainBundle) {
    NSString *origin = YNStoredOrigin();
    if (origin) return origin;
  }
  return YNOriginalBundleObjectForInfoDictionaryKey
      ? YNOriginalBundleObjectForInfoDictionaryKey(self, selector, key)
      : nil;
}

static NSURLRequest *YNRewriteRequest(NSURLRequest *request) {
  NSURL *rewritten = YNRewriteURL(request.URL);
  if (!request || rewritten == request.URL || [rewritten isEqual:request.URL]) return request;
  NSMutableURLRequest *copy = request.mutableCopy;
  copy.URL = rewritten;
  return copy;
}

static void YNPresentInvalidOrigin(UIViewController *controller) {
  UIAlertController *alert = [UIAlertController
      alertControllerWithTitle:@"Invalid Server URL"
                       message:@"Use an HTTPS origin without a path, query, username, or password. HTTP is allowed only for loopback, .local, and private-network servers."
                preferredStyle:UIAlertControllerStyleAlert];
  [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                            style:UIAlertActionStyleDefault
                                          handler:nil]];
  [controller presentViewController:alert animated:YES completion:nil];
}

static void YNBeginOriginPreflight(UIViewController *controller,
                                   BOOL retryAfterPermissionTransition);
static void YNPresentOriginEditor(UIViewController *controller);

static void YNPresentOriginUnavailable(UIViewController *controller) {
  if (!controller.view.window || controller.presentedViewController) return;
  UIAlertController *alert = [UIAlertController
      alertControllerWithTitle:@"Can't Reach Private Server"
                       message:@"Allow Local Network access, confirm this device and the server are on the same network, and verify the Server URL. This check did not send login credentials or create an account."
                preferredStyle:UIAlertControllerStyleAlert];
  __weak UIViewController *weakController = controller;
  [alert addAction:[UIAlertAction actionWithTitle:@"Retry"
                                            style:UIAlertActionStyleDefault
                                          handler:^(__unused UIAlertAction *action) {
    UIViewController *strongController = weakController;
    if (strongController) YNBeginOriginPreflight(strongController, NO);
  }]];
  [alert addAction:[UIAlertAction actionWithTitle:@"Server URL"
                                            style:UIAlertActionStyleDefault
                                          handler:^(__unused UIAlertAction *action) {
    UIViewController *strongController = weakController;
    if (strongController) YNPresentOriginEditor(strongController);
  }]];
  [alert addAction:[UIAlertAction actionWithTitle:@"Settings"
                                            style:UIAlertActionStyleDefault
                                          handler:^(__unused UIAlertAction *action) {
    NSURL *settings = [NSURL URLWithString:UIApplicationOpenSettingsURLString];
    if (settings) [UIApplication.sharedApplication openURL:settings
                                                   options:@{}
                                         completionHandler:nil];
  }]];
  [controller presentViewController:alert animated:YES completion:nil];
}

static void YNBeginOriginPreflight(UIViewController *controller,
                                   BOOL retryAfterPermissionTransition) {
  NSString *origin = YNStoredOrigin();
  NSURLComponents *components =
      origin ? [NSURLComponents componentsWithString:origin] : nil;
  // Public HTTPS origins do not participate in iOS Local Network privacy.
  // Only probe a stored local-development origin, and never synthesize one.
  if (!controller || !components ||
      !YNIsPrivateDevelopmentHost(components.host)) {
    return;
  }
  NSString *activeOrigin = objc_getAssociatedObject(
      controller, YNOriginPreflightOriginKey);
  if ([activeOrigin isEqualToString:origin]) return;
  NSURLSessionTask *activeTask = objc_getAssociatedObject(
      controller, YNOriginPreflightTaskKey);
  [activeTask cancel];
  objc_setAssociatedObject(controller, YNOriginPreflightTaskKey, nil,
                           OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  objc_setAssociatedObject(controller, YNOriginPreflightTokenKey, nil,
                           OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  objc_setAssociatedObject(controller, YNOriginPreflightOriginKey, nil,
                           OBJC_ASSOCIATION_COPY_NONATOMIC);

  NSURL *healthURL = YNHealthURL(origin);
  if (!healthURL) return;
  NSMutableURLRequest *request = [NSMutableURLRequest
      requestWithURL:healthURL
         cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
     timeoutInterval:8.0];
  request.HTTPMethod = @"GET";
  __weak UIViewController *weakController = controller;
  NSObject *token = [NSObject new];
  NSURLSessionDataTask *task = [NSURLSession.sharedSession
      dataTaskWithRequest:request
        completionHandler:^(__unused NSData *data, NSURLResponse *response,
                            NSError *error) {
    dispatch_async(dispatch_get_main_queue(), ^{
      UIViewController *strongController = weakController;
      if (!strongController) return;
      if (objc_getAssociatedObject(strongController,
                                   YNOriginPreflightTokenKey) == token) {
        objc_setAssociatedObject(strongController, YNOriginPreflightTaskKey,
                                 nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(strongController, YNOriginPreflightTokenKey,
                                 nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(strongController, YNOriginPreflightOriginKey,
                                 nil, OBJC_ASSOCIATION_COPY_NONATOMIC);
      } else {
        return;
      }
      NSInteger status = [(NSHTTPURLResponse *)response statusCode];
      if (!error && status >= 200 && status < 300) return;

      // The first LAN request can be consumed by the system permission
      // transition. Retry one harmless health request after that transition;
      // never retry login credentials or account creation.
      if (retryAfterPermissionTransition) {
        YNBeginOriginPreflight(strongController, NO);
      } else {
        YNPresentOriginUnavailable(strongController);
      }
    });
  }];
  objc_setAssociatedObject(controller, YNOriginPreflightTaskKey, task,
                           OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  objc_setAssociatedObject(controller, YNOriginPreflightTokenKey, token,
                           OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  objc_setAssociatedObject(controller, YNOriginPreflightOriginKey, origin,
                           OBJC_ASSOCIATION_COPY_NONATOMIC);
  [task resume];
}

static void YNPresentOriginEditor(UIViewController *controller) {
  if (!YNSharedDefaults()) {
    UIAlertController *unavailable = [UIAlertController
        alertControllerWithTitle:@"Server URL Unavailable"
                         message:@"The current signature does not provide a shared App Group. Re-sign the app and both widget extensions with the same App Group."
                  preferredStyle:UIAlertControllerStyleAlert];
    [unavailable addAction:[UIAlertAction actionWithTitle:@"OK"
                                                    style:UIAlertActionStyleDefault
                                                  handler:nil]];
    [controller presentViewController:unavailable animated:YES completion:nil];
    return;
  }

  UIAlertController *alert = [UIAlertController
      alertControllerWithTitle:@"Server URL"
                       message:@"Enter the origin for your YNAB-compatible server. Login, account creation, and all request paths remain handled by the app."
                preferredStyle:UIAlertControllerStyleAlert];
  [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
    field.text = YNStoredOrigin() ?: @"";
    field.placeholder = @"http://192.168.0.224:9090";
    field.keyboardType = UIKeyboardTypeURL;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.spellCheckingType = UITextSpellCheckingTypeNo;
  }];
  [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                            style:UIAlertActionStyleCancel
                                          handler:nil]];
  __weak UIViewController *weakController = controller;
  [alert addAction:[UIAlertAction actionWithTitle:@"Save"
                                            style:UIAlertActionStyleDefault
                                          handler:^(__unused UIAlertAction *action) {
    NSString *origin = YNNormalizeOrigin(alert.textFields.firstObject.text);
    if (!origin) {
      dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *strongController = weakController;
        if (strongController) YNPresentInvalidOrigin(strongController);
      });
      return;
    }
    NSUserDefaults *shared = YNSharedDefaults();
    [shared setObject:origin forKey:YNOriginDefaultsKey];
    NSString *installToken = YNCurrentInstallToken();
    if (installToken.length > 0) {
      [shared setObject:installToken forKey:YNOriginInstallTokenDefaultsKey];
    }
    YNBeginOriginPreflight(weakController, YES);
  }]];
  [controller presentViewController:alert animated:YES completion:nil];
}

static id YNObjectIvar(id object, const char *name) {
  if (!object) return nil;
  Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
  return ivar ? object_getIvar(object, ivar) : nil;
}

static void YNNoOpTemplateAction(__unused id action) {
}

static UIButton *YNNativeServerTextButton(void) {
  // This is the exact stock ButtonTemplate constructor used by the native
  // Forgot Password action. Its address and Swift string-object bindings are
  // supplied by the admitted artifact profile at compile time. The factory is
  // called synchronously from each controller's main-thread viewDidLoad.
  uintptr_t factoryAddress = YNRuntimeAddress(YN_BUTTON_TEMPLATE_VM_ADDRESS);
  uint64_t titleReference =
      YNImmortalStringReference(YN_FORGOT_TITLE_OBJECT_VM_ADDRESS);
  uint64_t accessibilityReference =
      YNImmortalStringReference(YN_FORGOT_ACCESSIBILITY_OBJECT_VM_ADDRESS);
  if (!factoryAddress || !titleReference || !accessibilityReference) return nil;
  YNButtonTemplateFactory factory = (YNButtonTemplateFactory)factoryAddress;
  UIButton *button = factory(
      YN_FORGOT_TITLE_COUNT_AND_FLAGS,
      titleReference,
      0, UINT64_C(0xC0), 0, 0,
      YN_FORGOT_ACCESSIBILITY_COUNT_AND_FLAGS,
      accessibilityReference,
      (void *)YNNoOpTemplateAction, NULL);
  if (![button isKindOfClass:UIButton.class] ||
      ![NSStringFromClass(button.class) hasSuffix:YNNativeTextActionClassSuffix] ||
      !button.configuration) {
    return nil;
  }

  UIButtonConfiguration *configuration = [button.configuration copy];
  configuration.title = @"Server URL";
  button.configuration = configuration;
  button.accessibilityLabel = @"Server URL";
  button.accessibilityHint = @"Choose the YNAB account server";
  button.accessibilityValue = YNStoredOrigin() ?: @"YNAB";
  button.accessibilityIdentifier = @"ynab_private_server_origin";
  // ButtonTemplate assigns horizontal hugging priority 750, the same priority
  // as the stock login stack's preferred-width constraint. A second native
  // text action at that priority can make Auto Layout prefer the buttons'
  // intrinsic width and collapse the entire form. Keep the stock stack as the
  // width owner without introducing a device-specific width constraint.
  [button setContentHuggingPriority:UILayoutPriorityDefaultHigh - 1.0f
                             forAxis:UILayoutConstraintAxisHorizontal];
  return button;
}

static UIButton *YNInstallServerButton(UIViewController *controller,
                                       const void *associationKey,
                                       const char *positionAnchorIvar,
                                       BOOL constrainToStackWidth,
                                       BOOL useZeroSpacing) {
  UIButton *existing = objc_getAssociatedObject(controller, associationKey);
  UIStackView *stack = YNObjectIvar(controller, "$__lazy_storage_$_stackView");
  UIButton *positionAnchor = YNObjectIvar(controller, positionAnchorIvar);
  if (![stack isKindOfClass:UIStackView.class]) return nil;
  BOOL hasArrangedPositionAnchor =
      [positionAnchor isKindOfClass:UIButton.class] &&
      [stack.arrangedSubviews containsObject:positionAnchor];
  if (!hasArrangedPositionAnchor) return nil;

  UIButton *button = existing ?: YNNativeServerTextButton();
  if (!button) return nil;
  if (!existing) {
    [button addTarget:controller
               action:NSSelectorFromString(@"ynab_editServerOrigin:")
     forControlEvents:UIControlEventTouchUpInside];
  }
  if ([stack.arrangedSubviews containsObject:button]) {
    [stack removeArrangedSubview:button];
    [button removeFromSuperview];
  }
  NSUInteger anchorIndex = [stack.arrangedSubviews indexOfObject:positionAnchor];
  CGFloat precedingSpacing = stack.spacing;
  if (anchorIndex > 0) {
    UIView *precedingView = stack.arrangedSubviews[anchorIndex - 1];
    CGFloat customSpacing = [stack customSpacingAfterView:precedingView];
    if (customSpacing >= 0) precedingSpacing = customSpacing;
  }
  [stack insertArrangedSubview:button atIndex:anchorIndex + 1];
  if (constrainToStackWidth && !existing) {
    // Create Account's stock stack is leading-aligned. Its native submit
    // button explicitly owns the stack width and center-X, so give the
    // adjacent text action the same horizontal layout contract instead of
    // leaving it at its title's intrinsic width.
    [NSLayoutConstraint activateConstraints:@[
      [button.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
      [button.centerXAnchor constraintEqualToAnchor:stack.centerXAnchor],
    ]];
  }
  [stack setCustomSpacing:useZeroSpacing ? 0.0 : precedingSpacing
                afterView:positionAnchor];
  objc_setAssociatedObject(controller, associationKey, button,
                           OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  return button;
}

typedef void (^YNArrangedSubviewObserver)(UIView *);

static void YNArmServerButtonPlacement(UIViewController *controller,
                                       const void *associationKey,
                                       const char *positionAnchorIvar,
                                       BOOL constrainToStackWidth,
                                       BOOL useZeroSpacing) {
  if (YNInstallServerButton(controller, associationKey, positionAnchorIvar,
                            constrainToStackWidth, useZeroSpacing)) {
    return;
  }

  UIStackView *stack = YNObjectIvar(controller, "$__lazy_storage_$_stackView");
  if (![stack isKindOfClass:UIStackView.class]) return;

  // SignInViewController adds Create a New Account asynchronously after its
  // viewDidLoad returns. Observe that exact source-owned stack mutation and
  // install immediately after the stock anchor is arranged. The observer is
  // attached only to this controller's stack and removes itself after firing.
  __weak UIViewController *weakController = controller;
  YNArrangedSubviewObserver observer = ^(UIView *addedView) {
    UIViewController *strongController = weakController;
    if (!strongController) return;
    UIView *anchor = YNObjectIvar(strongController, positionAnchorIvar);
    if (addedView != anchor) return;
    UIStackView *ownedStack =
        YNObjectIvar(strongController, "$__lazy_storage_$_stackView");
    objc_setAssociatedObject(ownedStack, YNArrangedSubviewObserverKey, nil,
                             OBJC_ASSOCIATION_COPY_NONATOMIC);
    YNInstallServerButton(strongController, associationKey,
                          positionAnchorIvar, constrainToStackWidth,
                          useZeroSpacing);
  };
  objc_setAssociatedObject(stack, YNArrangedSubviewObserverKey, observer,
                           OBJC_ASSOCIATION_COPY_NONATOMIC);
}

static void YNInstallSignInServerButton(UIViewController *controller) {
  // The initial sign-in surface has no Create a New Account action. Install
  // synchronously after Forgot Password so Server URL is available during the
  // controller's own viewDidLoad on every sign-in variant.
  UIButton *button = YNInstallServerButton(
      controller, YNSignInButtonKey,
      "$__lazy_storage_$_forgotPasswordButton", NO, YES);
  if (!button) return;

  UIStackView *stack = YNObjectIvar(controller, "$__lazy_storage_$_stackView");
  if (![stack isKindOfClass:UIStackView.class]) return;

  // The logged-out variant adds the exact controller-owned Create a New
  // Account action asynchronously. If it is already arranged, relocate the
  // same Server URL button now; otherwise move it during that one source-owned
  // stack mutation. Never create a second action.
  UIButton *createAccount =
      YNObjectIvar(controller, "$__lazy_storage_$_createAccountButton");
  if ([createAccount isKindOfClass:UIButton.class] &&
      [stack.arrangedSubviews containsObject:createAccount]) {
    YNInstallServerButton(controller, YNSignInButtonKey,
                          "$__lazy_storage_$_createAccountButton", NO, YES);
    return;
  }

  __weak UIViewController *weakController = controller;
  YNArrangedSubviewObserver observer = ^(UIView *addedView) {
    UIViewController *strongController = weakController;
    if (!strongController) return;
    UIView *anchor = YNObjectIvar(
        strongController, "$__lazy_storage_$_createAccountButton");
    if (addedView != anchor) return;
    UIStackView *ownedStack =
        YNObjectIvar(strongController, "$__lazy_storage_$_stackView");
    objc_setAssociatedObject(ownedStack, YNArrangedSubviewObserverKey, nil,
                             OBJC_ASSOCIATION_COPY_NONATOMIC);
    YNInstallServerButton(strongController, YNSignInButtonKey,
                          "$__lazy_storage_$_createAccountButton", NO, YES);
  };
  objc_setAssociatedObject(stack, YNArrangedSubviewObserverKey, observer,
                           OBJC_ASSOCIATION_COPY_NONATOMIC);
}

static void YNAddArrangedSubview(id self, SEL selector, UIView *view) {
  if (YNOriginalAddArrangedSubview) {
    YNOriginalAddArrangedSubview(self, selector, view);
  }
  YNArrangedSubviewObserver observer =
      objc_getAssociatedObject(self, YNArrangedSubviewObserverKey);
  if (observer) observer(view);
}

static void YNEditServerOrigin(id self, SEL selector, id sender) {
  (void)selector;
  (void)sender;
  YNPresentOriginEditor((UIViewController *)self);
}

static void YNPatchedSignInViewDidLoad(id self, SEL selector) {
  if (YNOriginalSignInViewDidLoad) YNOriginalSignInViewDidLoad(self, selector);
  YNInstallSignInServerButton(self);
  YNBeginOriginPreflight(self, YES);
}

static void YNPatchedCreateAccountViewDidLoad(id self, SEL selector) {
  if (YNOriginalCreateAccountViewDidLoad) {
    YNOriginalCreateAccountViewDidLoad(self, selector);
  }
  YNArmServerButtonPlacement(self, YNCreateAccountButtonKey,
                             "$__lazy_storage_$_signUpButton", YES, NO);
  YNBeginOriginPreflight(self, YES);
}

static BOOL YNPatchedShouldSkipSubscribeFlow(id self, SEL selector) {
  // A valid stored private origin selects a server whose entitlement decision
  // is authoritative, so the Stock purchase screen is not part of signup.
  // With no valid private origin, preserve Stock's exact build/debug behavior.
  if (YNStoredOrigin()) return YES;
  return YNOriginalShouldSkipSubscribeFlow
      ? YNOriginalShouldSkipSubscribeFlow(self, selector)
      : NO;
}

static BOOL YNOverrideInstanceMethod(Class cls, SEL selector, IMP replacement,
                                     IMP *original) {
  Method method = class_getInstanceMethod(cls, selector);
  if (!method) return NO;
  IMP current = method_getImplementation(method);
  if (class_addMethod(cls, selector, replacement, method_getTypeEncoding(method))) {
    *original = current;
  } else {
    *original = method_setImplementation(method, replacement);
  }
  return *original != NULL;
}

static NSURLSessionDataTask *YNDataTaskWithRequest(
    id self, SEL selector, NSURLRequest *request) {
  return YNOriginalDataTaskWithRequest(self, selector, YNRewriteRequest(request));
}

static NSURLSessionDataTask *YNDataTaskWithRequestCompletion(
    id self, SEL selector, NSURLRequest *request,
    void (^completion)(NSData *, NSURLResponse *, NSError *)) {
  return YNOriginalDataTaskWithRequestCompletion(
      self, selector, YNRewriteRequest(request), completion);
}

static NSURLSessionDataTask *YNDataTaskWithURL(id self, SEL selector, NSURL *url) {
  return YNOriginalDataTaskWithURL(self, selector, YNRewriteURL(url));
}

static NSURLSessionDataTask *YNDataTaskWithURLCompletion(
    id self, SEL selector, NSURL *url,
    void (^completion)(NSData *, NSURLResponse *, NSError *)) {
  return YNOriginalDataTaskWithURLCompletion(
      self, selector, YNRewriteURL(url), completion);
}

static NSURLSessionUploadTask *YNUploadTaskWithData(
    id self, SEL selector, NSURLRequest *request, NSData *data) {
  return YNOriginalUploadTaskWithData(
      self, selector, YNRewriteRequest(request), data);
}

static NSURLSessionUploadTask *YNUploadTaskWithDataCompletion(
    id self, SEL selector, NSURLRequest *request, NSData *data,
    void (^completion)(NSData *, NSURLResponse *, NSError *)) {
  return YNOriginalUploadTaskWithDataCompletion(
      self, selector, YNRewriteRequest(request), data, completion);
}

static NSURLSessionUploadTask *YNUploadTaskWithFile(
    id self, SEL selector, NSURLRequest *request, NSURL *fileURL) {
  return YNOriginalUploadTaskWithFile(
      self, selector, YNRewriteRequest(request), fileURL);
}

static NSURLSessionUploadTask *YNUploadTaskWithFileCompletion(
    id self, SEL selector, NSURLRequest *request, NSURL *fileURL,
    void (^completion)(NSData *, NSURLResponse *, NSError *)) {
  return YNOriginalUploadTaskWithFileCompletion(
      self, selector, YNRewriteRequest(request), fileURL, completion);
}

static NSURLSessionDownloadTask *YNDownloadTaskWithRequest(
    id self, SEL selector, NSURLRequest *request) {
  return YNOriginalDownloadTaskWithRequest(
      self, selector, YNRewriteRequest(request));
}

static NSURLSessionDownloadTask *YNDownloadTaskWithRequestCompletion(
    id self, SEL selector, NSURLRequest *request,
    void (^completion)(NSURL *, NSURLResponse *, NSError *)) {
  return YNOriginalDownloadTaskWithRequestCompletion(
      self, selector, YNRewriteRequest(request), completion);
}

static NSURLSessionDownloadTask *YNDownloadTaskWithURL(
    id self, SEL selector, NSURL *url) {
  return YNOriginalDownloadTaskWithURL(self, selector, YNRewriteURL(url));
}

static NSURLSessionDownloadTask *YNDownloadTaskWithURLCompletion(
    id self, SEL selector, NSURL *url,
    void (^completion)(NSURL *, NSURLResponse *, NSError *)) {
  return YNOriginalDownloadTaskWithURLCompletion(
      self, selector, YNRewriteURL(url), completion);
}

static BOOL YNReplaceSessionMethod(SEL selector, IMP replacement, IMP *original) {
  Method method = class_getInstanceMethod(NSURLSession.class, selector);
  if (!method) return NO;
  *original = method_setImplementation(method, replacement);
  return *original != NULL;
}

static void YNInstallNetworkHooks(void) {
  YNReplaceSessionMethod(@selector(dataTaskWithRequest:),
      (IMP)YNDataTaskWithRequest, (IMP *)&YNOriginalDataTaskWithRequest);
  YNReplaceSessionMethod(@selector(dataTaskWithRequest:completionHandler:),
      (IMP)YNDataTaskWithRequestCompletion,
      (IMP *)&YNOriginalDataTaskWithRequestCompletion);
  YNReplaceSessionMethod(@selector(dataTaskWithURL:),
      (IMP)YNDataTaskWithURL, (IMP *)&YNOriginalDataTaskWithURL);
  YNReplaceSessionMethod(@selector(dataTaskWithURL:completionHandler:),
      (IMP)YNDataTaskWithURLCompletion,
      (IMP *)&YNOriginalDataTaskWithURLCompletion);
  YNReplaceSessionMethod(@selector(uploadTaskWithRequest:fromData:),
      (IMP)YNUploadTaskWithData, (IMP *)&YNOriginalUploadTaskWithData);
  YNReplaceSessionMethod(@selector(uploadTaskWithRequest:fromData:completionHandler:),
      (IMP)YNUploadTaskWithDataCompletion,
      (IMP *)&YNOriginalUploadTaskWithDataCompletion);
  YNReplaceSessionMethod(@selector(uploadTaskWithRequest:fromFile:),
      (IMP)YNUploadTaskWithFile, (IMP *)&YNOriginalUploadTaskWithFile);
  YNReplaceSessionMethod(@selector(uploadTaskWithRequest:fromFile:completionHandler:),
      (IMP)YNUploadTaskWithFileCompletion,
      (IMP *)&YNOriginalUploadTaskWithFileCompletion);
  YNReplaceSessionMethod(@selector(downloadTaskWithRequest:),
      (IMP)YNDownloadTaskWithRequest, (IMP *)&YNOriginalDownloadTaskWithRequest);
  YNReplaceSessionMethod(@selector(downloadTaskWithRequest:completionHandler:),
      (IMP)YNDownloadTaskWithRequestCompletion,
      (IMP *)&YNOriginalDownloadTaskWithRequestCompletion);
  YNReplaceSessionMethod(@selector(downloadTaskWithURL:),
      (IMP)YNDownloadTaskWithURL, (IMP *)&YNOriginalDownloadTaskWithURL);
  YNReplaceSessionMethod(@selector(downloadTaskWithURL:completionHandler:),
      (IMP)YNDownloadTaskWithURLCompletion,
      (IMP *)&YNOriginalDownloadTaskWithURLCompletion);
}

static void YNInstallAuthenticationUIHooks(void) {
  Class signIn = YNClass(@"YNAB_Evergreen.SignInViewController",
                         @"_TtC14YNAB_Evergreen20SignInViewController");
  Class createAccount = YNClass(@"YNAB_Evergreen.CreateAccountViewController",
                                @"_TtC14YNAB_Evergreen27CreateAccountViewController");
  Class appStatus = NSClassFromString(@"YBAppStatus");
  SEL editSelector = NSSelectorFromString(@"ynab_editServerOrigin:");
  YNOverrideInstanceMethod(UIStackView.class, @selector(addArrangedSubview:),
      (IMP)YNAddArrangedSubview, (IMP *)&YNOriginalAddArrangedSubview);
  if (signIn) {
    class_addMethod(signIn, editSelector, (IMP)YNEditServerOrigin, "v@:@");
    YNOverrideInstanceMethod(signIn, @selector(viewDidLoad),
        (IMP)YNPatchedSignInViewDidLoad, (IMP *)&YNOriginalSignInViewDidLoad);
  }
  if (createAccount) {
    class_addMethod(createAccount, editSelector, (IMP)YNEditServerOrigin, "v@:@");
    YNOverrideInstanceMethod(createAccount, @selector(viewDidLoad),
        (IMP)YNPatchedCreateAccountViewDidLoad,
        (IMP *)&YNOriginalCreateAccountViewDidLoad);
  }
  if (appStatus) {
    YNOverrideInstanceMethod(appStatus, @selector(shouldSkipSubscribeFlow),
        (IMP)YNPatchedShouldSkipSubscribeFlow,
        (IMP *)&YNOriginalShouldSkipSubscribeFlow);
  }
}

static void YNInstallAuthoritativeConfigurationHook(void) {
  Class mainBundleClass = object_getClass(NSBundle.mainBundle);
  YNOverrideInstanceMethod(mainBundleClass,
      @selector(objectForInfoDictionaryKey:),
      (IMP)YNBundleObjectForInfoDictionaryKey,
      (IMP *)&YNOriginalBundleObjectForInfoDictionaryKey);
}

__attribute__((constructor)) static void YNInitializeServerOrigin(void) {
  YNReconcileOriginOwnership();
  // Install this before application startup. The stock Swift URL initializer
  // reads YB_APP_SERVER once and SharedLibraryManager passes that URL directly
  // into the JavaScript API configuration.
  YNInstallAuthoritativeConfigurationHook();
  YNInstallNetworkHooks();
  // The dylib constructor runs before UIApplicationMain. Install controller
  // hooks synchronously so the first authentication controller is born with
  // the source-owned Server URL action; no post-load scan or delayed overlay
  // is required.
  YNInstallAuthenticationUIHooks();
}

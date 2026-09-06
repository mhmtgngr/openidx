#
# CocoaPods spec for the OpenIDX engine plugin.
#
# The Go engine ships as `Engine.xcframework`, produced by:
#   gomobile bind -target=ios -o Engine.xcframework ./agent/mobile
# Drop it at ios/Frameworks/Engine.xcframework (see README.md). CI's
# client-mobile-build.yml builds the xcframework, copies it into place, then
# runs `flutter build ios --no-codesign`.
#
Pod::Spec.new do |s|
  s.name             = 'openidx_engine'
  s.version          = '0.1.0'
  s.summary          = 'OpenIDX Go engine gomobile bridge for Flutter (iOS).'
  s.description      = 'Bridges Dart to the OpenIDX engine (agent/mobile) via Engine.xcframework.'
  s.homepage         = 'https://github.com/openidx/openidx'
  s.license          = { :type => 'Apache-2.0' }
  s.author           = { 'OpenIDX' => 'engineering@openidx.example' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'
  s.swift_version = '5.0'

  # Link the gomobile-produced xcframework. It must exist at build time; CI
  # stages it before `pod install`.
  s.vendored_frameworks = 'Frameworks/Engine.xcframework'

  # libresolv, for the Go toolchain the engine will eventually be built with.
  #
  # go1.26's darwin resolver calls res_9_ninit / res_9_nsearch / res_9_nclose,
  # which live in libresolv. A gomobile static framework does not declare that
  # link requirement itself, so raising the mobile workflows' GO_VERSION to
  # 1.26 broke `flutter build ios` on exactly those three undefined symbols —
  # a green job turned red by a version bump that nothing in this plugin
  # needed. Both workflows went back to 1.25.x and `agent/go.mod` deliberately
  # pins a patched 1.25 toolchain, so nothing here needs libresolv *today*.
  #
  # Declaring it now anyway: it costs an unused system-library reference on
  # 1.25 (libresolv ships in the iOS SDK), and it means the next person who
  # has a reason to move the agent module to 1.26 does not have to rediscover
  # this from three undefined symbols. CocoaPods folds s.libraries into the
  # aggregate target's OTHER_LDFLAGS, so the app link — where the symbols
  # actually surface — gets the flag, not just this pod.
  s.libraries = 'resolv'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end

require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', '..', '..', 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'OidxZiti'
  s.version        = package['version'] || '1.0.0'
  s.summary        = 'OpenIDX embedded OpenZiti endpoint (Expo module)'
  s.description    = 'Wraps the CZiti Swift SDK so the OpenIDX app is a first-class OpenZiti identity.'
  s.author         = 'OpenIDX'
  s.homepage       = 'https://github.com/mhmtgngr/openidx'
  s.platforms      = { :ios => '15.1', :tvos => '15.1' }
  s.source         = { git: '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'
  # OpenZiti Swift SDK. Pin the exact version verified against the enroll/dial
  # API used in OidxZitiModule.swift before the first EAS build.
  s.dependency 'CZiti', '~> 1.4'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }

  s.source_files = '**/*.{h,m,mm,swift,hpp,cpp}'
end

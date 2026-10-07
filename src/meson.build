flathub_authenticator_sources = [
  'main.c',
]

flathub_authenticator_deps = [
  dependency('gio-2.0', version: '>= 2.68'),
  dependency('gio-unix-2.0'),
  dependency('libsoup-3.0'),
  dependency('json-glib-1.0'),
  dependency('libsecret-1'),
]

gnome = import('gnome')

flatpak_authenticator_dbus_src = gnome.gdbus_codegen('org.freedesktop.Flatpak.Authenticator',
  sources: ['org.freedesktop.Flatpak.Authenticator.xml'],
  interface_prefix: 'org.freedesktop',
)

application_dbus_src = gnome.gdbus_codegen('org.freedesktop.Application',
  sources: ['org.freedesktop.Application.xml'],
  interface_prefix: 'org.freedesktop',
)

executable('flathub-authenticator',
  flathub_authenticator_sources,
  flatpak_authenticator_dbus_src,
  application_dbus_src,
  dependencies: flathub_authenticator_deps,
  install: true,
)

authenticator_test = executable('test-authenticator',
  '../tests/test-authenticator.c',
  flatpak_authenticator_dbus_src,
  application_dbus_src,
  dependencies: flathub_authenticator_deps,
)
test('Authenticator', authenticator_test)

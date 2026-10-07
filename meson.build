project('flathub-authenticator', 'c',
          version: '0.1.0',
    meson_version: '>= 0.59.0',
  default_options: [ 'warning_level=2',
                     'c_std=gnu11',
                   ],
)

i18n = import('i18n')

gnome = import('gnome')

config_h = configuration_data()
config_h.set_quoted('FRONTEND_URL', get_option('frontend_url'))
config_h.set_quoted('BACKEND_URL', get_option('api_url'))
config_h.set10('ALLOW_INSECURE_LOCALHOST', get_option('allow_insecure_localhost'))
config_h.set_quoted('PROGRAM_NAME', meson.project_name())
config_h.set_quoted('PROGRAM_VERSION', meson.project_version())
configure_file(
  output: 'flathub_authenticator-config.h',
  configuration: config_h,
)
add_project_arguments([
  '-I' + meson.build_root(),
  '-DG_LOG_DOMAIN="@0@"'.format(meson.project_name()),
], language: 'c')


subdir('data')
subdir('src')

gnome.post_install(
  update_desktop_database: true,
)

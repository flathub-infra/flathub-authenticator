# flathub-authenticator

This is the repository authenticator app for Flathub. When you download an app that requires payment or allows donations,
this "app" will be downloaded automatically. It directs you to the Flathub website, where you can pay for the app, and
then returns the download token to the flatpak client.

A token for your account is saved so that updates don't require you to log in again.

## Why the browser?

Stripe, the payment processor Flathub uses, has a web-based frontend for making purchases. Native user interfaces for
accepting payments would be very complicated--not every available payment method is as simple as entering a card number
and PIN.

More importantly, we want to be DE-agnostic. Making a different native frontend for every desktop--or even making an
API sufficient to handle payments so each desktop can provide their own--would not be scalable, so using the Flathub
website is the next best way.

## Repository Configuration

### Building and testing

Install Meson, a C compiler, and development packages for GLib/GIO,
libsoup 3, JSON-GLib, and libsecret. Configure the frontend and API URLs
for your deployment, then build and run the regression tests:

```sh
meson setup build -Dfrontend_url=https://your-frontend.example \
  -Dapi_url=https://your-api.example
meson compile -C build
meson test -C build --print-errorlogs
```

The default endpoints are HTTPS on localhost ports 3000 and 8000; they are
development placeholders, not production Flathub purchase endpoints.
TLS certificate validation remains enabled. For local HTTP development only:

```sh
meson setup build -Dallow_insecure_localhost=true \
  -Dfrontend_url=http://localhost:3000 -Dapi_url=http://localhost:8000
```

HTTP is rejected outside loopback even with this option enabled. URLs must
not contain credentials, query strings, or fragments. Backend redirects are
not followed, so token-bearing requests cannot be redirected to another host.
Tests use a local mock backend and an in-memory token store; they do not
access your keyring or contact the production service.

The Flatpak manifest uses Freedesktop 26.08 and its maintained libraries.
Build the package (including tests) with:

```sh
flatpak install --user flathub org.flatpak.Builder \
  org.freedesktop.Sdk//26.08 org.freedesktop.Platform//26.08
flatpak run org.flatpak.Builder --user --force-clean builddir org.flathub.Authenticator.json
```

Set deployment URLs through the main module's `config-opts` when packaging
for a real repository.

### Enabling the authenticator

To configure the repository to use this app, it must first be uploaded as part of the repo. Then, run the following
command:

```sh
flatpak build-update-repo --authenticator-name=org.flathub.Authenticator --authenticator-install <repo path>
```

You can check the configuration with:

```sh
ostree summary -v <repo path>
```

It should contain the keys `xa.authenticator-name: 'org.flathub.Authenticator'` and `xa.authenticator-install: true`.

## Related Documentation

[org.freedesktop.Flatpak.Authenticator D-Bus API](https://docs.flatpak.org/en/latest/libflatpak-api-reference.html?highlight=authenticator#gdbus-org.freedesktop.Flatpak.Authenticator)

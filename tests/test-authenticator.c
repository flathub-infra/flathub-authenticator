/* Exercise the real handlers without accessing the user's keyring or bus. */
#include <libsecret/secret.h>
static char *stored_token;
static gboolean
test_password_store (const SecretSchema *schema, const char *collection,
                     const char *label, const char *password,
                     GCancellable *cancellable, GError **error, ...)
{
  (void) schema;
  (void) collection;
  (void) label;
  (void) cancellable;
  (void) error;
  g_free (stored_token);
  stored_token = g_strdup (password);
  return TRUE;
}
#define secret_password_store_sync test_password_store
#define main authenticator_main
#include "../src/main.c"
#undef main

static unsigned int response_count;
static unsigned int response_code;
static char *webflow_url;
static unsigned int backend_status = SOUP_STATUS_OK;

static void
response_cb (FlatpakAuthenticatorRequest *impl,
             unsigned int code,
             GVariant *results,
             gpointer data)
{
  (void) impl;
  (void) results;
  (void) data;
  response_count ++;
  response_code = code;
}

static void
webflow_cb (FlatpakAuthenticatorRequest *impl,
            const char *url,
            GVariant *options,
            gpointer data)
{
  (void) impl;
  (void) options;
  (void) data;
  g_free (webflow_url);
  webflow_url = g_strdup (url);
}

static ActiveRequest *
new_request (void)
{
  ActiveRequest *req = g_new0 (ActiveRequest, 1);
  const char *refs[] = { "app/org.example.App/x86_64/stable&return=evil#fragment", NULL };

  req->ref_count = 1;
  req->cancellable = g_cancellable_new ();
  req->request_impl = flatpak_authenticator_request_skeleton_new ();
  req->refs = g_strdupv ((char **) refs);
  active_requests ++;
  response_count = 0;
  g_clear_pointer (&stored_token, g_free);
  g_clear_pointer (&webflow_url, g_free);
  g_signal_connect (req->request_impl, "response", G_CALLBACK (response_cb), NULL);
  g_signal_connect (req->request_impl, "webflow", G_CALLBACK (webflow_cb), NULL);
  return req;
}

static void
test_webflow_url (void)
{
  ActiveRequest *req = new_request ();
  g_autoptr(GUri) uri = NULL;
  g_autoptr(GHashTable) query = NULL;
  g_autoslist(GUri) uris = NULL;
  g_autofree char *return_uri = NULL;

  redirect_to_frontend (req);
  uri = g_uri_parse (webflow_url, G_URI_FLAGS_ENCODED_QUERY, NULL);
  query = soup_form_decode (g_uri_get_query (uri));
  uris = soup_server_get_uris (req->return_server);
  return_uri = g_uri_to_string (uris->data);
  g_assert_cmpuint (g_hash_table_size (query), ==, 2);
  g_assert_cmpstr (g_hash_table_lookup (query, "refs"), ==, req->refs[0]);
  g_assert_cmpstr (g_hash_table_lookup (query, "return"), ==, return_uri);
  g_assert_null (g_uri_get_fragment (uri));
  end_request_with_cancellation (req);
  g_assert_cmpint (active_requests, ==, 0);
}

static void
server_cb (SoupServer *server, SoupServerMessage *msg, const char *path,
           GHashTable *query, gpointer data)
{
  (void) server;
  (void) path;
  (void) query;
  soup_server_message_set_status (msg, backend_status, NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
                             data, strlen (data));
}

static gboolean
test_timeout (gpointer data)
{
  (void) data;
  g_error ("Timed out waiting for request completion");
  return G_SOURCE_REMOVE;
}

static void
run_backend (const char *body, gboolean cancel)
{
  g_autoptr(SoupServer) server = soup_server_new (NULL, NULL);
  g_autoptr(SoupSession) session = soup_session_new ();
  g_autoslist(GUri) uris = NULL;
  g_autofree char *uri = NULL;
  g_autoptr(GError) error = NULL;
  ActiveRequest *req = new_request ();
  DownloadTokenRequest *data = g_new0 (DownloadTokenRequest, 1);
  unsigned int timeout;
  g_autoptr(GProxyResolver) proxy = g_simple_proxy_resolver_new (NULL, NULL);

  g_object_set (session, "proxy-resolver", proxy, NULL);
  req->didWebflow = TRUE;
  soup_server_add_handler (server, NULL, server_cb, (void *) body, NULL);
  g_assert_true (soup_server_listen_local (server, 0, 0, &error));
  g_assert_no_error (error);
  uris = soup_server_get_uris (server);
  uri = g_uri_to_string (uris->data);
  data->message = soup_message_new ("POST", uri);
  data->request = req;
  req->ref_count ++;
  soup_session_send_async (session, data->message, G_PRIORITY_DEFAULT, req->cancellable,
                           on_download_token_request_sent, data);
  if (cancel)
    end_request_with_cancellation (req);
  timeout = g_timeout_add_seconds (5, test_timeout, NULL);
  while (active_requests != 0)
    g_main_context_iteration (NULL, TRUE);
  g_source_remove (timeout);
  g_assert_cmpuint (response_count, ==, 1);
}

static void
test_cancel_pending (void)
{
  run_backend ("{\"token\":\"download\"}", TRUE);
  g_assert_cmpuint (response_code, ==, 1);
}

static void
test_backend_success (void)
{
  run_backend ("{\"token\":\"download\"}", FALSE);
  g_assert_cmpuint (response_code, ==, 0);
}

static void
test_backend_invalid (void)
{
  const char *bodies[] = { "broken", "null", "[]", "{}",
    "{\"token\":42}", "{\"token\":null}", "{\"update-token\":{}}",
    "{\"token\":\"\"}", "{\"token\":\"bad\\r\\ntoken\"}",
    "{\"token\":\"good\",\"update-token\":false}",
    "{\"missing_appids\":false}", "{\"missing_appids\":[42]}",
    "{\"update-token\":\"must-not-store\"}" };
  for (size_t i = 0; i < G_N_ELEMENTS (bodies); i ++)
    {
      run_backend (bodies[i], FALSE);
      g_assert_cmpuint (response_code, ==, 2);
      g_assert_null (stored_token);
    }
}

static void
test_backend_rotation (void)
{
  run_backend ("{\"token\":\"download\",\"update-token\":\"rotated\"}", FALSE);
  g_assert_cmpuint (response_code, ==, 0);
  g_assert_cmpstr (stored_token, ==, "rotated");
}

static void
test_backend_http_error (void)
{
  const unsigned int statuses[] = { 302, 401, 403, 429, 500 };
  for (size_t i = 0; i < G_N_ELEMENTS (statuses); i ++)
    {
      backend_status = statuses[i];
      run_backend ("{\"token\":\"must-not-accept\",\"update-token\":\"must-not-store\"}", FALSE);
      g_assert_cmpuint (response_code, ==, 2);
      g_assert_null (stored_token);
    }
  backend_status = SOUP_STATUS_OK;
}

static void
http_finished (GObject *source, GAsyncResult *result, gpointer data)
{
  gboolean *finished = data;
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) body = soup_session_send_and_read_finish (SOUP_SESSION (source), result, &error);
  g_assert_no_error (error);
  *finished = TRUE;
}

static void
callback_http (const char *base, const char *path, const char *method,
               const char *origin, unsigned int status)
{
  g_autoptr(SoupSession) session = soup_session_new ();
  g_autoptr(GProxyResolver) proxy = g_simple_proxy_resolver_new (NULL, NULL);
  g_autofree char *url = g_strconcat (base, path, NULL);
  g_autoptr(SoupMessage) msg = soup_message_new (method, url);
  gboolean finished = FALSE;
  unsigned int timeout = g_timeout_add_seconds (5, test_timeout, NULL);

  g_object_set (session, "proxy-resolver", proxy, NULL);
  if (origin != NULL)
    soup_message_headers_replace (soup_message_get_request_headers (msg), "Origin", origin);
  soup_session_send_and_read_async (session, msg, G_PRIORITY_DEFAULT, NULL, http_finished, &finished);
  while (!finished)
    g_main_context_iteration (NULL, TRUE);
  g_source_remove (timeout);
  g_assert_cmpuint (soup_message_get_status (msg), ==, status);
}

static void
test_callbacks (void)
{
  ActiveRequest *req = new_request ();
  const char *queries[] = { "", "unknown=x", "token=", "download-token=",
                           "download-token=bad%0D%0Atoken", "token=&download-token=good" };
  g_autoslist(GUri) uris = NULL;
  g_autofree char *base = NULL;

  redirect_to_frontend (req);
  uris = soup_server_get_uris (req->return_server);
  base = g_uri_to_string (uris->data);

  for (size_t i = 0; i < G_N_ELEMENTS (queries); i ++)
    {
      g_autofree char *path = g_strconcat ("success?", queries[i], NULL);
      callback_http (base, path, "GET", NULL, 400);
      g_assert_cmpuint (response_count, ==, 0);
      g_assert_null (stored_token);
    }
  callback_http (base, "cancel", "POST", NULL, 405);
  callback_http (base, "cancel", "GET", "https://evil.example", 403);
  callback_http (base, "success/extra?download-token=good", "GET", NULL, 404);
  g_assert_cmpuint (response_count, ==, 0);
  callback_http (base, "success?download-token=good&unknown=ignored", "GET", NULL, 200);
  g_assert_cmpuint (response_code, ==, 0);
  g_assert_cmpuint (response_count, ==, 1);
  g_assert_cmpint (active_requests, ==, 0);
}

static void
test_endpoints (void)
{
  const char *invalid[] = { "", "not a URL", "file:///tmp/token", "http://example.com",
    "https://user:pass@example.com", "https://example.com?x=y", "https://example.com#fragment",
    "http://localhost.evil.example", "http://192.168.1.1" };
  const char *local[] = { "http://localhost:3000", "http://127.0.0.1:8000", "http://[::1]:8000" };

  g_assert_true (valid_endpoint ("https://example.com/api", FALSE));
  for (size_t i = 0; i < G_N_ELEMENTS (invalid); i ++)
    {
      g_assert_false (valid_endpoint (invalid[i], FALSE));
      g_assert_false (valid_endpoint (invalid[i], TRUE));
    }
  for (size_t i = 0; i < G_N_ELEMENTS (local); i ++)
    {
      g_assert_false (valid_endpoint (local[i], FALSE));
      g_assert_true (valid_endpoint (local[i], TRUE));
    }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/webflow/url", test_webflow_url);
  g_test_add_func ("/backend/cancel-pending", test_cancel_pending);
  g_test_add_func ("/backend/success", test_backend_success);
  g_test_add_func ("/backend/invalid", test_backend_invalid);
  g_test_add_func ("/backend/rotation", test_backend_rotation);
  g_test_add_func ("/backend/http-error", test_backend_http_error);
  g_test_add_func ("/webflow/callbacks", test_callbacks);
  g_test_add_func ("/transport/endpoints", test_endpoints);
  int result = g_test_run ();
  g_free (webflow_url);
  g_free (stored_token);
  return result;
}

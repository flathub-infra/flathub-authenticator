/* main.c
 *
 * Copyright 2022 James Westman
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <glib/gi18n.h>
#include <libsoup/soup.h>
#include <json-glib/json-glib.h>
#include <libsecret/secret.h>

#include "flathub_authenticator-config.h"
#include "org.freedesktop.Flatpak.Authenticator.h"
#include "org.freedesktop.Application.h"


static GDBusObjectManagerServer *manager = NULL;
static int active_requests = 0;


typedef struct {
  SoupServer *return_server;
  FlatpakAuthenticatorRequest *request_impl;
  char *update_token;
  GStrv refs;
  gboolean didWebflow;
  unsigned int ref_count;
  gboolean completed;
  GCancellable *cancellable;
  gboolean callback_received;
} ActiveRequest;

typedef struct {
  ActiveRequest *request;
  SoupMessage *message;
} DownloadTokenRequest;


static void
active_request_free (ActiveRequest *req)
{
  if (--req->ref_count != 0)
    return;

  g_clear_object (&req->request_impl);
  g_clear_object (&req->return_server);
  g_clear_object (&req->cancellable);
  g_clear_pointer (&req->refs, g_strfreev);
  g_clear_pointer (&req->update_token, g_free);
  g_free (req);
  active_requests --;
}

static void
active_request_complete (ActiveRequest *req)
{
  const char *path;

  req->completed = TRUE;
  g_cancellable_cancel (req->cancellable);
  g_signal_handlers_disconnect_by_data (req->request_impl, req);
  path = g_dbus_interface_skeleton_get_object_path (G_DBUS_INTERFACE_SKELETON (req->request_impl));
  if (manager != NULL && path != NULL)
    g_dbus_object_manager_server_unexport (manager, path);
  if (req->return_server != NULL)
    {
      soup_server_remove_handler (req->return_server, "/success");
      soup_server_remove_handler (req->return_server, "/cancel");
      /* The request-finished reference keeps the server alive until the
       * callback response has been sent. Disconnecting here truncates it. */
    }
  active_request_free (req);
}


static void redirect_to_frontend (ActiveRequest *request);
static void on_download_token_request_sent (GObject      *source_object,
                                            GAsyncResult *res,
                                            gpointer      user_data);
static void clear_token (ActiveRequest *request);
static void end_request_with_error (ActiveRequest *req,
                                    const char    *error_message);
static void end_request_with_token (ActiveRequest *req,
                                    const char     *token);
static void end_request_with_cancellation (ActiveRequest *req);
static void handle_return_request (SoupServer        *server,
                                   SoupServerMessage *msg,
                                   const char        *path,
                                   GHashTable        *query,
                                   gpointer           user_data);
static void handle_cancel_request (SoupServer        *server,
                                   SoupServerMessage *msg,
                                   const char        *path,
                                   GHashTable        *query,
                                   gpointer           user_data);
static void get_download_token (ActiveRequest *req);

static void on_download_token_message_read (GObject      *object,
                                            GAsyncResult *result,
                                            gpointer      user_data);


static const SecretSchema secret_schema = {
  .name = "org.flathub.Authenticator",
  .flags = SECRET_SCHEMA_NONE,
};

static void
store_update_token (const char *update_token)
{
  g_autoptr(GError) error = NULL;

  g_debug ("Storing update token");

  if (!secret_password_store_sync (&secret_schema, SECRET_COLLECTION_DEFAULT,
                                   "Update token for Flathub", update_token, NULL, &error,
                                   NULL))
    g_warning ("Failed to store the update token: %s", error->message);
}

/* Retrieves the update token, which must be freed with secret_password_free() if it is not NULL. */
static char *
retrieve_update_token ()
{
  g_autoptr(GError) error = NULL;
  char *token;

  g_debug ("Retrieving update token...");

  token = secret_password_lookup_sync (&secret_schema, NULL, &error, NULL);

  if (error != NULL)
    {
      g_warning ("Failed to retrieve the update token: %s", error->message);
      return NULL;
    }

  if (token == NULL)
    g_debug ("No update token found.");
  else
    g_debug ("Found.");

  return token;
}


static gboolean
handle_close (FlatpakAuthenticator  *authenticator,
              GDBusMethodInvocation *invocation,
              gpointer               user_data)
{
  ActiveRequest *request = (ActiveRequest *)user_data;

  g_assert (IS_FLATPAK_AUTHENTICATOR_REQUEST (authenticator));
  g_assert (G_IS_DBUS_METHOD_INVOCATION (invocation));

  g_dbus_method_invocation_return_value (invocation, NULL);
  end_request_with_cancellation (request);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}


static gboolean
handle_request_ref_token (FlatpakAuthenticator     *authenticator,
                          GDBusMethodInvocation    *invocation,
                          G_GNUC_UNUSED const char *handle_token,
                          G_GNUC_UNUSED GVariant   *authenticator_options,
                          G_GNUC_UNUSED const char *remote,
                          G_GNUC_UNUSED const char *remote_uri,
                          GVariant                 *refs,
                          G_GNUC_UNUSED GVariant   *options,
                          G_GNUC_UNUSED const char *parent_window,
                          G_GNUC_UNUSED gpointer    user_data)
{
  g_autoptr(GStrvBuilder) ref_name_builder = g_strv_builder_new ();
  g_auto(GStrv) ref_names = NULL;
  g_autoptr(GDBusObjectSkeleton) object = NULL;
  g_autoptr(FlatpakAuthenticatorRequest) impl = NULL;
  g_autofree char *obj_path = NULL;
  g_autofree char *sender = NULL;
  g_autoptr(GError) error = NULL;
  ActiveRequest *request;
  char *update_token = NULL;

  GVariant *result = NULL;
  GVariantIter iter;
  gchar *ref;

  g_assert (IS_FLATPAK_AUTHENTICATOR (authenticator));
  g_assert (G_IS_DBUS_METHOD_INVOCATION (invocation));

  /* Get list of flatpak refs from the D-Bus call */
  g_variant_iter_init (&iter, refs);
  while (g_variant_iter_loop (&iter, "(ssia{sv})", &ref, NULL, NULL, NULL))
    g_strv_builder_add (ref_name_builder, ref);

  ref_names = g_strv_builder_end (ref_name_builder);

  /* Create the request object */
  sender = g_strdup (g_dbus_method_invocation_get_sender (invocation));
  sender = g_strdelimit (sender, ".", '_');
  obj_path = g_strdup_printf ("/org/freedesktop/Flatpak/Authenticator/request/%s/%s", &sender[1], handle_token);
  object = g_dbus_object_skeleton_new (obj_path);

  impl = flatpak_authenticator_request_skeleton_new ();
  g_dbus_object_skeleton_add_interface (object, G_DBUS_INTERFACE_SKELETON (impl));

  g_dbus_object_manager_server_export (manager, object);

  request = g_new0 (ActiveRequest, 1);
  request->ref_count = 1;
  request->cancellable = g_cancellable_new ();
  active_requests ++;
  request->request_impl = g_object_ref (impl);
  request->refs = g_strdupv (ref_names);

  g_signal_connect (impl, "handle-close", G_CALLBACK (handle_close), request);

  /* Return the path of the request object */
  result = g_variant_new_parsed ("(%o,)", obj_path);
  g_dbus_method_invocation_return_value (invocation, result);

  update_token = retrieve_update_token ();
  if (update_token != NULL)
    {
      request->update_token = g_strdup (update_token);
      secret_password_free (update_token);
      get_download_token (request);
    }
  else
    redirect_to_frontend (request);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}


static void
redirect_to_frontend (ActiveRequest *request)
{
  g_autoptr(GError) error = NULL;
  g_autoslist(GUri) uris = NULL;
  g_autofree char *url = NULL;
  g_autofree char *return_uri = NULL;
  g_autofree char *ref_string = NULL;
  g_autofree char *escaped_refs = NULL;
  g_autofree char *escaped_return_uri = NULL;

  /* Prevent infinite loops if something goes wrong somewhere */
  if (request->didWebflow)
    {
      end_request_with_error (request, "previous webflow failed, not going to try again");
      return;
    }

  /* Create a web server to listen for the end of the webflow */
  request->return_server = soup_server_new (NULL, NULL);
  soup_server_listen_local (request->return_server, 0, 0, &error);
  if (error != NULL)
    {
      end_request_with_error (request, "failed to create socket to listen for webflow response");
      return;
    }

  soup_server_add_handler (request->return_server, "/success", handle_return_request, request, NULL);
  soup_server_add_handler (request->return_server, "/cancel", handle_cancel_request, request, NULL);

  /* We need to hold a reference to the server whenever a request is open. Otherwise, we might free the ActiveRequest
     (and thus the server) while it's still sending a response. */
  g_signal_connect (request->return_server, "request-started", G_CALLBACK (g_object_ref), NULL);
  g_signal_connect (request->return_server, "request-finished", G_CALLBACK (g_object_unref), NULL);
  g_signal_connect (request->return_server, "request-aborted", G_CALLBACK (g_object_unref), NULL);

  uris = soup_server_get_uris (request->return_server);
  g_assert (g_slist_length (uris) > 0);
  return_uri = g_uri_to_string (uris->data);

  /* Emit the Webflow signal */
  request->didWebflow = TRUE;
  ref_string = g_strjoinv (";", request->refs);
  escaped_refs = g_uri_escape_string (ref_string, NULL, FALSE);
  escaped_return_uri = g_uri_escape_string (return_uri, NULL, FALSE);
  url = g_strdup_printf (FRONTEND_URL "/purchase?refs=%s&return=%s",
                         escaped_refs, escaped_return_uri);
  g_debug ("Redirecting to %s", url);
  flatpak_authenticator_request_emit_webflow (request->request_impl, url, g_variant_new ("a{sv}", NULL));
}


static void
set_callback_status (SoupServerMessage *msg, unsigned int status)
{
  soup_server_message_set_status (msg, status, NULL);
  soup_server_message_set_response (msg, NULL, SOUP_MEMORY_STATIC, NULL, 0);
}

static gboolean
validate_callback (ActiveRequest *req, SoupServerMessage *msg,
                   const char *path, const char *expected_path)
{
  SoupMessageHeaders *headers = soup_server_message_get_response_headers (msg);
  const char *origin = soup_message_headers_get_one (soup_server_message_get_request_headers (msg), "Origin");
  g_autoptr(GUri) frontend = g_uri_parse (FRONTEND_URL, G_URI_FLAGS_NONE, NULL);
  g_autofree char *frontend_origin = g_uri_join (G_URI_FLAGS_NONE,
    g_uri_get_scheme (frontend), NULL, g_uri_get_host (frontend),
    g_uri_get_port (frontend), "", NULL, NULL);

  /* Origins have no trailing slash. */
  if (g_str_has_suffix (frontend_origin, "/"))
    frontend_origin[strlen (frontend_origin) - 1] = '\0';
  if (origin != NULL && strcmp (origin, frontend_origin) != 0)
    {
      set_callback_status (msg, SOUP_STATUS_FORBIDDEN);
      return FALSE;
    }
  if (strcmp (path, expected_path) != 0)
    {
      set_callback_status (msg, SOUP_STATUS_NOT_FOUND);
      return FALSE;
    }
  if (strcmp (soup_server_message_get_method (msg), SOUP_METHOD_GET) != 0)
    {
      soup_message_headers_replace (headers, "Allow", "GET");
      set_callback_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED);
      return FALSE;
    }
  if (req->callback_received)
    {
      set_callback_status (msg, SOUP_STATUS_CONFLICT);
      return FALSE;
    }
  soup_message_headers_replace (headers, "Access-Control-Allow-Origin", frontend_origin);
  soup_message_headers_replace (headers, "Cache-Control", "no-store");
  return TRUE;
}

static gboolean
valid_token (const char *token)
{
  if (token == NULL || *token == '\0' || strlen (token) > 16384)
    return FALSE;
  for (const unsigned char *p = (const unsigned char *) token; *p; p ++)
    if (*p <= 0x20 || *p == 0x7f)
      return FALSE;
  return TRUE;
}

static void
handle_return_request (G_GNUC_UNUSED SoupServer        *server,
                       SoupServerMessage               *msg,
                       G_GNUC_UNUSED const char        *path,
                       GHashTable                      *query,
                       gpointer                         user_data)
{
  ActiveRequest *req = (ActiveRequest *)user_data;
  char *token, *download_token;

  g_debug ("Handling return request");

  if (!validate_callback (req, msg, path, "/success"))
    return;

  token = query != NULL ? g_hash_table_lookup (query, "token") : NULL;
  download_token = query != NULL ? g_hash_table_lookup (query, "download-token") : NULL;
  if ((token == NULL && download_token == NULL) ||
      (token != NULL && !valid_token (token)) ||
      (download_token != NULL && !valid_token (download_token)))
    {
      set_callback_status (msg, SOUP_STATUS_BAD_REQUEST);
      return;
    }

  req->callback_received = TRUE;
  set_callback_status (msg, SOUP_STATUS_OK);
  flatpak_authenticator_request_emit_webflow_done (req->request_impl, g_variant_new ("a{sv}", NULL));
  if (token != NULL)
    {
      g_debug ("Received update token");

      g_clear_pointer (&req->update_token, g_free);
      req->update_token = g_strdup (token);

      store_update_token (token);
    }

  if (download_token != NULL)
    {
      g_debug ("Received download token");
      end_request_with_token (req, download_token);
      return;
    }
  else
    get_download_token (req);

}


static void
handle_cancel_request (G_GNUC_UNUSED SoupServer        *server,
                       SoupServerMessage               *msg,
                       G_GNUC_UNUSED const char        *path,
                       G_GNUC_UNUSED GHashTable        *query,
                       gpointer                         user_data)
{
  ActiveRequest *request = (ActiveRequest *)user_data;

  g_debug ("Handling cancel request");

  if (!validate_callback (request, msg, path, "/cancel"))
    return;

  request->callback_received = TRUE;
  set_callback_status (msg, SOUP_STATUS_OK);

  flatpak_authenticator_request_emit_webflow_done (request->request_impl, g_variant_new ("a{sv}", NULL));

  end_request_with_cancellation (request);

}


static void
get_download_token (ActiveRequest *request)
{
  g_autoptr(SoupSession) session = NULL;
  g_autoptr(SoupMessage) msg = NULL;
  g_autoptr(JsonBuilder) builder = NULL;
  g_autoptr(JsonNode) node = NULL;
  g_autofree char *request_body = NULL;
  g_autoptr(GBytes) body = NULL;
  gsize i, n;

  g_debug ("Getting download token");

  builder = json_builder_new ();
  json_builder_begin_object (builder);
    json_builder_set_member_name (builder, "appids");
    json_builder_begin_array (builder);
      for (i = 0, n = g_strv_length (request->refs); i < n; i ++)
        json_builder_add_string_value (builder, request->refs[i]);
    json_builder_end_array (builder);

    json_builder_set_member_name (builder, "update_token");
    json_builder_add_string_value (builder, request->update_token);
  json_builder_end_object (builder);
  node = json_builder_get_root (builder);
  request_body = json_to_string (node, FALSE);

  msg = soup_message_new (SOUP_METHOD_POST, BACKEND_URL "/purchases/generate-download-token");
  soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
  body = g_bytes_new (request_body, strlen (request_body));
  soup_message_set_request_body_from_bytes (msg, "application/json", body);

  session = soup_session_new ();
  g_object_set (G_OBJECT (session),
                "user-agent", PROGRAM_NAME " " PROGRAM_VERSION,
                "timeout", 30,
                NULL);

  {
    DownloadTokenRequest *data = g_new0 (DownloadTokenRequest, 1);
    data->request = request;
    request->ref_count ++;
    data->message = g_object_ref (msg);

    soup_session_send_async (session,
                             msg,
                             G_PRIORITY_DEFAULT,
                             request->cancellable,
                             on_download_token_request_sent,
                             data);
  }
}


static void
on_download_token_request_sent (GObject      *object,
                                GAsyncResult *res,
                                gpointer      user_data)
{
  SoupSession *session = SOUP_SESSION (object);
  DownloadTokenRequest *data = user_data;
  g_autoptr(JsonParser) parser = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GInputStream) stream = NULL;
  g_autoptr(GOutputStream) output_stream = NULL;

  stream = soup_session_send_finish (session, res, &error);
  if (data->request->completed)
    goto done;

  if (stream == NULL)
    {
      end_request_with_error (data->request, "failed to contact token server");
      goto done;
    }

  if (!SOUP_STATUS_IS_SUCCESSFUL (soup_message_get_status (data->message)))
    {
      if (soup_message_get_status (data->message) == SOUP_STATUS_UNAUTHORIZED ||
          soup_message_get_status (data->message) == SOUP_STATUS_FORBIDDEN)
        clear_token (data->request);
      else
        end_request_with_error (data->request, "token server returned an HTTP error");
      goto done;
    }

  parser = json_parser_new ();
  json_parser_load_from_stream_async (parser,
                                      stream,
                                      data->request->cancellable,
                                      on_download_token_message_read,
                                      data);
  return;

done:
  active_request_free (data->request);
  g_object_unref (data->message);
  g_free (data);
}


static void
on_download_token_message_read (GObject      *source_object,
                                GAsyncResult *result,
                                gpointer      user_data)
{
  JsonParser *parser = JSON_PARSER (source_object);
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) bytes = NULL;
  DownloadTokenRequest *data = user_data;
  ActiveRequest *request = data->request;
  JsonNode *node;
  JsonObject *object;
  const char *token = NULL;
  const char *update_token = NULL;
  JsonArray *missing = NULL;

  gboolean parsed = json_parser_load_from_stream_finish (parser, result, &error);

  if (request->completed)
    goto done;

  if (!parsed)
    goto failed;

  node = json_parser_get_root (parser);

  if (!JSON_NODE_HOLDS_OBJECT (node))
    goto failed;

  object = json_node_get_object (node);
  if ((node = json_object_get_member (object, "missing_appids")))
    {
      if (!JSON_NODE_HOLDS_ARRAY (node))
        goto failed;
      missing = json_node_get_array (node);
      for (size_t i = 0; i < json_array_get_length (missing); i ++)
        {
          JsonNode *item = json_array_get_element (missing, i);
          if (!JSON_NODE_HOLDS_VALUE (item) || json_node_get_value_type (item) != G_TYPE_STRING)
            goto failed;
        }
    }

  if ((node = json_object_get_member (object, "token")))
    {
      if (!JSON_NODE_HOLDS_VALUE (node) ||
          json_node_get_value_type (node) != G_TYPE_STRING ||
          !valid_token (json_node_get_string (node)))
        goto failed;

      token = json_node_get_string (node);
    }

  if ((node = json_object_get_member (object, "update-token")))
    {
      if (!JSON_NODE_HOLDS_VALUE (node) ||
          json_node_get_value_type (node) != G_TYPE_STRING ||
          !valid_token (json_node_get_string (node)))
        goto failed;

      update_token = json_node_get_string (node);
    }

  if (token == NULL && (missing == NULL || json_array_get_length (missing) == 0))
    goto failed;
  if (update_token != NULL)
    store_update_token (update_token);
  if (missing != NULL && json_array_get_length (missing) != 0)
    redirect_to_frontend (request);
  else
    end_request_with_token (request, token);
  goto done;

failed:
  end_request_with_error (request, "invalid token server response");

done:
  active_request_free (request);
  g_object_unref (data->message);
  g_free (data);
}


static void
clear_token (ActiveRequest *request)
{
  g_debug ("Clearing update token");
  g_clear_pointer (&request->update_token, g_free);
  redirect_to_frontend (request);
}


static void
end_request_with_error (ActiveRequest *req,
                        const char    *error_message)
{
  GVariant *result = g_variant_new_parsed ("{'error-message': <{'error-message': %s}>}", error_message);
  flatpak_authenticator_request_emit_response (req->request_impl, 2, result);

  g_debug ("Request ended in failure: %s", error_message);
  active_request_complete (req);
}


static void
end_request_with_token (ActiveRequest *request,
                        const char    *token)
{
  GVariant *result = g_variant_new_parsed ("{'tokens': <{%s: %^as}>}", token, request->refs);
  flatpak_authenticator_request_emit_response (request->request_impl, 0, result);

  g_debug ("Request succeeded.");
  active_request_complete (request);
}


static void
end_request_with_cancellation (ActiveRequest *request)
{
  GVariant *result = g_variant_new_parsed ("@a{sv} {}");
  flatpak_authenticator_request_emit_response (request->request_impl, 1, result);

  g_debug ("Request cancelled by user.");
  active_request_complete (request);
}


static void
on_bus_acquired (GDBusConnection        *connection,
                 const char             *name,
                 G_GNUC_UNUSED gpointer  user_data)
{
  g_autoptr(GDBusObjectSkeleton) app = NULL;
  g_autoptr(Application) app_impl = NULL;
  g_autoptr(GDBusObjectSkeleton) object = NULL;
  g_autoptr(FlatpakAuthenticator) impl = NULL;

  g_assert (G_IS_DBUS_CONNECTION (connection));

  g_debug ("Bus acquired: %s", name);

  g_assert (manager == NULL);
  manager = g_dbus_object_manager_server_new ("/");

  object = g_dbus_object_skeleton_new ("/org/freedesktop/Flatpak/Authenticator");
  impl = flatpak_authenticator_skeleton_new ();
  flatpak_authenticator_set_version (impl, 1);
  g_signal_connect (impl, "handle-request-ref-tokens", G_CALLBACK (handle_request_ref_token), NULL);
  g_dbus_object_skeleton_add_interface (object, G_DBUS_INTERFACE_SKELETON (impl));
  g_dbus_object_manager_server_export (manager, object);

  app = g_dbus_object_skeleton_new ("/org/flathub/Authenticator");
  app_impl = application_skeleton_new ();
  g_dbus_object_skeleton_add_interface (app, G_DBUS_INTERFACE_SKELETON (app_impl));
  g_dbus_object_manager_server_export (manager, app);

  g_dbus_object_manager_server_set_connection (manager, connection);
}


static void
on_name_acquired (GDBusConnection        *connection,
                  const char             *name,
                  G_GNUC_UNUSED gpointer  user_data)
{
  g_assert (G_IS_DBUS_CONNECTION (connection));

  g_debug ("Acquired name: %s", name);
}


static void
on_name_lost (GDBusConnection        *connection,
              const char             *name,
              G_GNUC_UNUSED gpointer  user_data)
{
  g_assert (G_IS_DBUS_CONNECTION (connection));

  g_debug ("Lost name: %s", name);
}


static gboolean
quit_timer (GMainLoop *loop)
{
  g_assert (active_requests >= 0);

  if (active_requests == 0)
    {
      g_main_loop_quit (loop);
      g_debug ("Shutting down due to inactivity");
    }

  return G_SOURCE_CONTINUE;
}

static gboolean
valid_endpoint (const char *url, gboolean allow_insecure_localhost)
{
  g_autoptr(GUri) uri = g_uri_parse (url, G_URI_FLAGS_NONE, NULL);
  g_autoptr(GInetAddress) address = NULL;

  if (uri == NULL || g_uri_get_host (uri) == NULL || *g_uri_get_host (uri) == '\0' ||
      g_uri_get_userinfo (uri) != NULL ||
      g_uri_get_query (uri) != NULL || g_uri_get_fragment (uri) != NULL)
    return FALSE;
  if (g_strcmp0 (g_uri_get_scheme (uri), "https") == 0)
    return TRUE;
  if (!allow_insecure_localhost || g_strcmp0 (g_uri_get_scheme (uri), "http") != 0)
    return FALSE;
  if (g_ascii_strcasecmp (g_uri_get_host (uri), "localhost") == 0)
    return TRUE;
  address = g_inet_address_new_from_string (g_uri_get_host (uri));
  return address != NULL && g_inet_address_get_is_loopback (address);
}


int
main (void)
{
  g_autoptr(GMainLoop) loop = NULL;
  guint id;

  if (!valid_endpoint (FRONTEND_URL, ALLOW_INSECURE_LOCALHOST) ||
      !valid_endpoint (BACKEND_URL, ALLOW_INSECURE_LOCALHOST))
    {
      g_printerr ("Configure HTTPS frontend_url and api_url endpoints. "
                  "HTTP loopback requires allow_insecure_localhost=true.\n");
      return 1;
    }

  loop = g_main_loop_new (NULL, FALSE);
  g_timeout_add_seconds (60, G_SOURCE_FUNC (quit_timer), loop);

  id = g_bus_own_name (G_BUS_TYPE_SESSION,
                       "org.flathub.Authenticator",
                       G_BUS_NAME_OWNER_FLAGS_NONE,
                       on_bus_acquired,
                       on_name_acquired,
                       on_name_lost,
                       NULL,
                       NULL);

  g_main_loop_run (loop);

  g_bus_unown_name (id);

  return 0;
}

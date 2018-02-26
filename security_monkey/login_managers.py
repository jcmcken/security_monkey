from flask_login import LoginManager
from flask_security.utils import config_value
from flask_security.core import AnonymousUser, _user_loader, _request_loader, _security
from datetime import datetime

ROLES = ['View', 'Comment', 'Justify', 'Admin']

def default_login_manager(anonymous_user, request_loader=None, user_loader=None):
    """
    Setup a LoginManager similar to the Flask-Security default. This does not
    initialize the app.
    """
    lm = LoginManager()
    lm.anonymous_user = anonymous_user or AnonymousUser
    lm.login_view = '%s.login' % config_value('BLUEPRINT_NAME', app=app)
    lm.user_loader(user_loader or _user_loader)
    lm.request_loader(request_loader or _request_loader)

    if config_value('FLASH_MESSAGES', app=app):
        lm.login_message, lm.login_message_category = config_value('MSG_LOGIN', app=app)
        lm.needs_refresh_message, lm.needs_refresh_message_category = config_value(
            'MSG_REFRESH', app=app)
    else:
        lm.login_message = None
        lm.needs_refresh_message = None

    return lm

def header_request_loader(request):
    """
    Set the login user to the HTTP header ``Remote-User``.

    Optionally, also set the user's e-mail to the header ``Remote-Email``, and
    the user's role to ``Remote-Role``.

    If the user does not yet exist in the user datastore, create it. If the
    attributes of that user differ from the headers, update them.

    NOTE: To receive the header ``Remote-User`` (etc.) from the frontend
    webserver, these values must be set in the WSGI environment. Setting the
    headers manually on the frontend will result in the wrong headers on the
    backend (e.g. setting ``Remote-User`` on the frontend becomes
    ``X-Remote-User`` on the backend)
    """
    remote_user = request.headers.get('Remote-User')
    email = request.headers.get('Remote-Email')
    role = request.headers.get('Remote-Role')

    if not remote_user:
        return

    datastore = _security.datastore

    user = datastore.find_user(id=remote_user)

    # create the user if it doesn't exist
    if not user:
        kwargs = {
          'id': remote_user,
          'confirmed_at': datetime.now(),
        }

        if email:
            kwargs['email'] = email

        if role in ROLES:
            kwargs['role'] = role

        return datastore.create_user(**kwargs)

    # user does exist, but maybe its attributes are wrong
    if email is not None and user.email != email:
        user.email = email
        datastore.put(user)
    if role is not None and user.role != role and role in ROLES:
        datastore.remove_role_from_user(user, user.role.name)
        datastore.add_role_to_user(user, role)
    return user

def create_header_login_manager(app):
    lm = default_login_manager(
      # with header-based auth, anonymous users are denied at the frontend proxy
      anonymous_user=None,
      # override Flask-Security default request loader
      request_loader=header_request_loader,
    )
    lm.init_app(app)
    return lm

_PROVIDERS = {
  'header': create_header_login_manager,
}

def get(name, default=None):
    return _PROVIDERS.get(name, default)

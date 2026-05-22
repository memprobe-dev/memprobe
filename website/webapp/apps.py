from django.apps import AppConfig


class WebappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'webapp'

    def ready(self):
        # Wire up the pre_save signal that scrubs SocialAccount.extra_data
        # on every write - defense-in-depth alongside the adapter.
        from . import signals  # noqa: F401

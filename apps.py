from django.apps import AppConfig


class DRFGNAPConfig(AppConfig):
    name = "drf_gnap"
    verbose_name = "DRF GNAP"

    def ready(self) -> None:
        from drf_gnap import checks  # noqa: F401 - register system checks
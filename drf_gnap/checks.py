"""Django system checks for drf-gnap configuration."""
from django.core.checks import Error, Warning, register


@register()
def check_gnap_settings(app_configs, **kwargs):  # type: ignore[no-untyped-def]
    from drf_gnap.settings import gnap_settings
    errors = []

    try:
        from django.conf import settings
        gnap_conf = getattr(settings, "GNAP", None)
        if gnap_conf is None:
            errors.append(
                Warning(
                    "GNAP settings are not configured.",
                    hint="Add a GNAP = {...} dict to your Django settings.",
                    id="drf_gnap.W001",
                )
            )
        else:
            if not gnap_conf.get("AS_URL"):
                errors.append(
                    Error(
                        "GNAP['AS_URL'] is not set.",
                        hint="Set GNAP['AS_URL'] to your Authorization Server's grant endpoint URI.",
                        id="drf_gnap.E001",
                    )
                )
            if not gnap_conf.get("CLIENT_KEY"):
                errors.append(
                    Error(
                        "GNAP['CLIENT_KEY'] is not set.",
                        hint="Set GNAP['CLIENT_KEY'] to your client's JWK or key path.",
                        id="drf_gnap.E002",
                    )
                )
    except Exception:
        pass

    return errors
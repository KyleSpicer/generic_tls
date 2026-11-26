from mythic_container.C2ProfileBase import *

from pathlib import Path
from ssl import TLSVersion, CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED

MARKER = b"__GENERICTLS_CONFIG_START__"
RESERVED_LEN = 4096  # total bytes reserved in the binary after the marker
LEN_PREFIX = 4  # bytes holding the config length

TLS_VERSIONS = {
    "1.2": TLSVersion.TLSv1_2,
    "1.3": TLSVersion.TLSv1_3,
}

CLIENT_AUTH = {"none": CERT_NONE, "optional": CERT_OPTIONAL, "required": CERT_REQUIRED}


class GenericTLS(C2Profile):
    name = "generic_tls"
    description = "Generic TLS Mythic C2 Profile"
    author = "@kylespicer"
    is_p2p = False  # is egress profile
    semver = "1.0.0"
    agent_icon_path = None
    dark_mode_agent_icon_path = None
    server_folder_path = Path(".") / "c2_code"
    server_binary_path = server_folder_path / "server.py"

    parameters = [
        C2ProfileParameter(
            name="callback_host", description="https://host", default_value="https://"
        ),
        C2ProfileParameter(
            name="callback_port", description="Port", default_value="443"
        ),
        C2ProfileParameter(
            name="get_uri", description="GET URI", default_value="index"
        ),
        C2ProfileParameter(
            name="post_uri", description="POST URI", default_value="data"
        ),
        C2ProfileParameter(
            name="callback_interval", description="Seconds", default_value="10"
        ),
        C2ProfileParameter(
            name="callback_jitter", description="Percent", default_value="23"
        ),
        C2ProfileParameter(
            name="killdate",
            description="YYYY-MM-DD",
            parameter_type=ParameterType.Date,
            default_value="365",
        ),
        C2ProfileParameter(
            name="AESPSK",
            description="Crypto key",
            parameter_type=ParameterType.ChooseOne,
            choices=["aes256_hmac", "none"],
            default_value="aes256_hmac",
        ),
        C2ProfileParameter(
            name="headers",
            description="HTTP headers",
            parameter_type=ParameterType.Dictionary,
            default_value=[],
        ),
    ]

    async def config_check(
        self, inputMsg: C2ConfigCheckMessage
    ) -> C2ConfigCheckMessageResponse:
        response = C2ConfigCheckMessageResponse(Success=True)
        # e.g., reject https host with port that your server isn't bound to
        return response

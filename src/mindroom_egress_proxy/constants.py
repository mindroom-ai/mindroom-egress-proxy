"""Shared constants for the MindRoom egress proxy."""

DEFAULT_PROXY_PORT = 3128
DEFAULT_POLICY_API_PORT = 8080
DEFAULT_NAMESPACE = "default"
DEFAULT_MAX_TTL_SECONDS = 6 * 60 * 60
DEFAULT_WORKER_CACHE_SECONDS = 30
DEFAULT_SQUID_CONFIG_PATH = "/etc/squid/squid.conf"
MAX_PORT = 65535
MAX_DNS_NAME_LENGTH = 253
MAX_DNS_LABEL_LENGTH = 63
MIN_DNS_LABELS = 2
MAX_REASON_CHARS = 500
WORKER_KEY_MIN_PARTS = 4
USER_AGENT_WORKER_KEY_MIN_PARTS = 5
SAFE_PORTS = {80, 443}
FORBIDDEN_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
}
FORBIDDEN_HOST_SUFFIXES = (
    ".localhost",
    ".svc",
    ".svc.cluster.local",
    ".cluster.local",
)
WORKER_ID_LABEL = "mindroom.ai/worker-id"
WORKER_KEY_ANNOTATION = "mindroom.ai/worker-key"

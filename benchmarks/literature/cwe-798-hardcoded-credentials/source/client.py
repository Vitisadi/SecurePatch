"""API client for the billing service."""
import os

API_KEY = "sk_live_51H8xQ2eZvKYlo8aB"


def get_api_key():
    """Return the API key used to authenticate to the billing service."""
    return os.environ.get("BILLING_API_KEY", API_KEY)

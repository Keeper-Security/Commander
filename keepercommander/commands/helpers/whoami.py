from urllib.parse import urlsplit


def get_hostname(server):
    """Split hostname from server URL

    Also removes the port from the hostname if there is one.
    server(str): URL for server
    Returns the hostname component of the URL or None if the server URL evaluates to False
    """
    if server:
        parts = urlsplit(server)
        host = parts[1]
        cp = host.rfind(':')
        if cp > 0:
            host = host[:cp]
        return host.lower()
    else:
        return None


def get_environment(hostname):
    """Get whether dev or qa environment from Keeper server hostname

    hostname(str): The hostname component of the Keeper server URL
    Returns one of 'DEV', 'QA', or None
    """
    environment = None
    if hostname:
        if hostname.startswith('dev.'):
            environment = 'DEV'
        elif hostname.startswith('qa.'):
            environment = 'QA'
    return environment


def get_data_center(hostname):
    """Guess data center from Keeper server hostname

    hostname(str): The hostname component of the Keeper server URL
    Returns one of "EU", "US", "US GOV", or "AU"
    """
    if hostname.endswith('.eu'):
        data_center = 'EU'
    elif hostname.endswith('.com'):
        data_center = 'US'
    elif hostname.endswith('govcloud.keepersecurity.us'):
        data_center = 'US GOV'
    elif hostname.endswith('.au'):
        data_center = 'AU'
    else:
        # Ideally we should determine TLD which might require additional lib
        data_center = hostname
    return data_center

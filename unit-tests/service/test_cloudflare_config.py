import unittest

from keepercommander.service.config.cloudflare_config import CloudflareConfigurator
from keepercommander.service.util.tunneling import get_tunnel_log_file


class TestCloudflareLogPath(unittest.TestCase):
    def test_health_check_reads_the_same_file_the_tunnel_writes_to(self):
        """_get_cloudflare_log_path() used to hardcode its own copy of the log path,
        which drifted out of sync when the tunnel log location moved to the shared
        service_logs dir - the health check kept reading the old, now-empty file and
        always timed out with 'status could not be determined'."""
        self.assertEqual(
            CloudflareConfigurator._get_cloudflare_log_path(),
            get_tunnel_log_file("cloudflare_tunnel_subprocess.log"),
        )


if __name__ == '__main__':
    unittest.main()

from unittest import TestCase, mock

from lemur.plugins.lemur_aws import acm_endpoints, cloudfront


class TestDiscoveryResponseShapes(TestCase):
    def test_gateway_load_balancer_skips_listener_discovery(self):
        with mock.patch.object(acm_endpoints.elb, "describe_listeners_v2") as listeners:
            self.assertEqual(acm_endpoints.get_elb_endpoints_v2(
                "123456789012", "us-east-1", {"Type": "gateway"}
            ), [])
        listeners.assert_not_called()

    def test_application_listener_errors_still_propagate(self):
        with mock.patch.object(acm_endpoints.elb, "describe_listeners_v2",
                               side_effect=RuntimeError("denied")):
            with self.assertRaisesRegex(RuntimeError, "denied"):
                acm_endpoints.get_elb_endpoints_v2(
                    "123456789012", "us-east-1",
                    {"Type": "application", "LoadBalancerArn": "alb"},
                )

    def test_empty_cloudfront_inventory_without_items(self):
        with mock.patch.object(cloudfront, "get_distributions", return_value={
            "DistributionList": {"Quantity": 0, "IsTruncated": False}
        }):
            self.assertEqual(cloudfront.get_all_distributions(account_number="123456789012"), [])

    def test_cloudfront_pagination_preserves_distributions(self):
        with mock.patch.object(cloudfront, "get_distributions", side_effect=[
            {"DistributionList": {"Quantity": 1, "Items": [{"Id": "first"}],
                                  "IsTruncated": True, "NextMarker": "next"}},
            {"DistributionList": {"Quantity": 1, "Items": [{"Id": "second"}],
                                  "IsTruncated": False}},
        ]) as pages:
            self.assertEqual(cloudfront.get_all_distributions(account_number="123456789012"),
                             [{"Id": "first"}, {"Id": "second"}])
        self.assertEqual(pages.call_args_list, [
            mock.call(account_number="123456789012"),
            mock.call(account_number="123456789012", Marker="next"),
        ])

    def test_cloudfront_api_errors_still_propagate(self):
        with mock.patch.object(cloudfront, "get_distributions", side_effect=RuntimeError("denied")), \
                mock.patch.object(cloudfront.metrics, "send"), \
                mock.patch.object(cloudfront, "capture_exception"):
            with self.assertRaisesRegex(RuntimeError, "denied"):
                cloudfront.get_all_distributions(account_number="123456789012")

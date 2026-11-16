import unittest

from live_gateway import CausalFeatureBuffer, parse_serial_line
from model_features import FEATURES


class ParseSerialLineTests(unittest.TestCase):
    def test_parses_current_receiver_record(self):
        record = parse_serial_line("12000,17,1,44,-45,1000,123,24.50,40.20,1002.1,1,0")

        self.assertEqual(record, (12000, 44.0, 123.0))

    def test_parses_authentication_failure_without_sensor_value(self):
        record = parse_serial_line("12001,-1,0,44,-45,1,0,0,0,0,0,0")

        self.assertEqual(record, (12001, 44.0, None))

    def test_skips_headers_and_malformed_records(self):
        self.assertIsNone(parse_serial_line("# t_ms,seq,auth_ok,len,rssi,iat_ms,current,temp,hum,press,pir,replay"))
        self.assertIsNone(parse_serial_line("12000,17,maybe,44,-45,1000,123,24.50,40.20,1002.1,1,0"))

    def test_feature_buffer_uses_training_feature_columns(self):
        features = CausalFeatureBuffer().push(12000, 44.0, 123.0)

        self.assertEqual(list(features), FEATURES)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python
import argparse
from monitoring import Monitor, Service, Time, Succeed, Delta
from monitoring.actions import Librato

__doc__='''
Example:
python Tests/test-action-librato.py -metric-name my.test.metric \
    -librato-user my@email.com \
    -librato-token xxxyyy
'''

parser = argparse.ArgumentParser(description='Test Librato Metrics action')
parser.add_argument('-metric-name', dest='metric_name', default='my.test.metric',
                    help='The name of the metric to send to librato')
parser.add_argument('-librato-user', dest='user', help='Librato username (usually an email address)')
parser.add_argument('-librato-token', dest='token', required=True,
                    help='Librato security token (Find it here https://metrics.librato.com/account)')
parser.add_argument('-source', dest='source', default='source01',
                    help='The name of the source. Usually a server name or a logical name for librato')

args = parser.parse_args()

action = Librato(args.metric_name,
                 user=args.user,
                 token=args.token,
                 source=args.source)

Monitor(
  Service(
    name=__file__[0].split(".")[0],
    monitor=(
      # We use delta for demo purpose, just b/c librato needs a numeric value
      Delta(Succeed(Time.s(5)), success=action)
    )
  )
).run()


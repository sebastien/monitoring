#!/usr/bin/env python
import argparse
from monitoring import Monitor, Service, Time, Print
from monitoring.rules import Jenkins

__doc__='''
Example:
python Tests/test-monitor-jenkins.py -jenkins-server-url http://my.jenkins.com:8080/ \
    -jenkins-user jenksina
    -jenkins-passw passwordina
'''

parser = argparse.ArgumentParser(description='Test jenkins monitor')
parser.add_argument('-jenkins-server-url', dest='server', required=True,
                    help='Example: http://my.jenkins.com:8080/')
parser.add_argument('-jenkins-user', dest='user', help='Jenkins username')
parser.add_argument('-jenkins-passw', dest='passw', help='Jenkins password')

args = parser.parse_args()

Monitor(
  Service(
    name = __file__[0].split(".")[0],
    monitor = (
      Jenkins(
        server=args.server,
        user=args.user,
        passw=args.passw,
        monitor_queue='global',
        freq=Time.m(1),
        fail=[Print("Error connecting to jenkins")],
        success=[Print("SUCCESS")]
      )
    )
  )
).run()

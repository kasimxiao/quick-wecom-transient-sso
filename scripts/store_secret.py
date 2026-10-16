#!/usr/bin/env python3
"""Store one customer's WeCom Secret using hidden input and AWS SecureString.

No secret is accepted in argv, printed, or saved locally. Requires boto3 and an
already authenticated AWS session. Existing parameters are never overwritten.
"""
import argparse
import getpass
import re
import sys

VERSION = '1.0.0'


def main():
    """Validate target account, prompt without echo, and create an encrypted parameter.

    Raises: ValueError for unsafe inputs; AWS errors are redacted by the entrypoint.
    """
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', action='version', version=VERSION)
    p.add_argument('--account', required=True, help='Expected 12-digit AWS account')
    p.add_argument('--region', required=True, help='SSM region')
    p.add_argument('--parameter', required=True, help='Customer-specific SSM path')
    p.add_argument('--kms-key-id', default='alias/aws/ssm', help='Approved encryption key')
    a = p.parse_args()
    if not (re.fullmatch(r'[0-9]{12}', a.account) and re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]', a.region)
            and re.fullmatch(r'/[A-Za-z0-9_.\-/]{3,200}', a.parameter)):
        raise ValueError('Invalid account, region or parameter path')
    if not sys.stdin.isatty():
        raise ValueError('Use an interactive terminal; never pipe a Secret')
    import boto3
    s = boto3.Session(region_name=a.region)
    if s.client('sts').get_caller_identity()['Account'] != a.account:
        raise ValueError('AWS account mismatch; no write performed')
    with __import__('warnings').catch_warnings():
        __import__('warnings').simplefilter('error', getpass.GetPassWarning)
        secret = getpass.getpass('WeCom application Secret (hidden input): ')
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', secret):
        raise ValueError('Invalid Secret format; no write performed')
    s.client('ssm').put_parameter(Name=a.parameter, Value=secret, Type='SecureString',
                                  KeyId=a.kms_key_id, Overwrite=False,
                                  Description='Customer WeCom broker application credential')
    secret = None
    print('Secret securely saved. No credential was printed. Continue with the configuration check.')


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('Cancelled.', file=sys.stderr)
        raise SystemExit(130)
    except Exception as e:
        code = getattr(e, 'response', {}).get('Error', {}).get('Code')
        print('Secret storage failed: ' + (str(e) if type(e) is ValueError else code or type(e).__name__), file=sys.stderr)
        raise SystemExit(1)

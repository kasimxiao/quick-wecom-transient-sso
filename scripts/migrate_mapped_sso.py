#!/usr/bin/env python3
"""Add guarded Desktop/Web session reuse, changing no Quick/IAM/employee resources."""
import argparse
import json
from pathlib import Path
import sys
import traceback
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import new_customer as n
import mapped_sso as sso
from scripts.migrate_mapped_transient import authenticate,contracts


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=['prepare','enable','verify','rollback'])
    parser.add_argument('--config',required=True);parser.add_argument('--snapshot',required=True)
    parser.add_argument('--admin-secret-id');parser.add_argument('--confirm-target')
    args=parser.parse_args();c=n.validate(json.loads(Path(args.config).read_text()))
    path=Path(args.snapshot);n.need(path.stat().st_mode&0o077==0,'Use a private mapping snapshot')
    snapshot=json.loads(path.read_text());policy=snapshot['policy']
    n.need(all(policy[a]==c[a] for a in ('realm','aws_account','corp_id','agent_id')),'Wrong snapshot target')
    if args.stage!='verify':n.need(args.confirm_target==c['aws_account']+'/'+c['realm'],'Confirm ACCOUNT/REALM')
    import boto3
    session=boto3.Session(region_name=c['region']);k=authenticate(c,session,args.admin_secret_id)
    if args.stage!='rollback':contracts(c,k,session,policy)
    if args.stage=='enable':
        try:result=sso.enable(k,snapshot)
        except Exception:
            sso.rollback(k,snapshot)
            raise ValueError('SSO cutover failed; prior mapped browser flow restored') from None
    else:result=getattr(sso,args.stage)(k,snapshot)
    print(json.dumps(result|{'stage':args.stage,'aws_quick_writes':False,'persistent_employee_writes':False,
        'real_desktop_one_scan_verified':False}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'failed':True,'type':type(error).__name__,'http_status':getattr(error,'code',None),
            'reason':str(error) if isinstance(error,ValueError) else 'Operation failed; response suppressed',
            'frames':[(Path(f.filename).name,f.lineno) for f in traceback.extract_tb(error.__traceback__)]}));raise SystemExit(1)

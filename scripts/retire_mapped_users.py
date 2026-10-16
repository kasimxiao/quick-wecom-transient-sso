#!/usr/bin/env python3
"""Retire exact approved legacy Keycloak users after transient SSO acceptance."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import new_customer as n
import mapped_cleanup as cleanup
import mapped_sso as sso
from migrate_mapped_transient import authenticate,contracts,write_private,legacy_manifest


def main():
    """Check, back up/delete, or verify; never write IAM or Quick resources."""
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage',choices=['check','apply','verify'])
    p.add_argument('--config',required=True);p.add_argument('--snapshot',required=True)
    p.add_argument('--directory');p.add_argument('--admin-secret-id');p.add_argument('--confirm-target')
    p.add_argument('--confirm-user',action='append',default=[])
    args=p.parse_args();c=legacy_manifest(json.loads(Path(args.config).read_text(),object_pairs_hook=n.w.unique_object))
    path=Path(args.snapshot);n.need(path.stat().st_mode&0o077==0,'Use a private snapshot')
    snapshot=json.loads(path.read_text());policy=snapshot['policy']
    n.need(all(policy[key]==c[key] for key in ('realm','aws_account','corp_id','agent_id')),'Wrong snapshot target')
    if args.stage=='apply':
        n.need(args.confirm_target==c['aws_account']+'/'+c['realm'],'Confirm ACCOUNT/REALM')
        n.need(args.directory and not Path(args.directory).exists(),'Use a new private backup directory')
    import boto3
    session=boto3.Session(region_name=c['region']);k=authenticate(c,session,args.admin_secret_id)
    contracts(c,k,session,policy)
    if args.stage=='apply':
        directory=Path(args.directory)
        def backup(value):
            directory.mkdir(mode=0o700)
            write_private(directory/'before.json',value)
            # Written before DELETE so an interrupted run can be verified without retrying.
            write_private(directory/'after-snapshot.json',value['candidate_snapshot'])
        result,updated=cleanup.retire(k,snapshot,args.confirm_user,backup)
        write_private(directory/'completed.json',result)
    else:
        if args.stage=='check':cleanup.retired_snapshot(snapshot)
        result=sso.verify(k,snapshot,True)
    print(json.dumps(result|{'stage':args.stage,'aws_quick_writes':False,'real_post_cleanup_scan_verified':False}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'failed':True,'type':type(error).__name__,'http_status':getattr(error,'code',None),
            'reason':str(error) if isinstance(error,ValueError) else 'Operation failed; private response suppressed',
            'action':'Do not blindly retry deletion. Inspect private backup and verify candidate snapshot.'}))
        raise SystemExit(1)

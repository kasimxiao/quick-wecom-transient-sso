"""Explicit retirement of backed-up legacy employees; no AWS/Quick writes."""
import copy
import mapped_transient as m
import mapped_sso as sso


def retired_snapshot(snapshot):
    """Return a separate zero-user verification baseline with stable policy.

    Args:
        snapshot (dict): Private, verified pre-retirement migration snapshot.
    Returns:
        dict: Copy with an integrity-bound retirement marker; identity rows unchanged.
    Raises:
        ValueError: Already retired, empty/ambiguous target, or identity mismatch.
    """
    policy=m.validate_policy(snapshot['policy']);m.need(not m.retired_user_ids(snapshot))
    m.need(snapshot['users'])
    for old in snapshot['users']:
        user=old['user'];matches=[row for row in policy['users'] if row['subject']==user['id']]
        m.need(len(matches)==1 and user.get('enabled') and not user.get('serviceAccountClientId'))
        row=matches[0];links=[x for x in old['links'] if x['identityProvider']=='wecom']
        m.need(row['enabled'] and row['username']==user['username'] and row['email']==user['email']
            and len(links)==1 and links[0]['userId']==row['wecom_user_id'])
    result=copy.deepcopy(snapshot)
    result['legacy_retirement']={'schema':1,'user_ids':sorted(x['user']['id'] for x in snapshot['users']),
        'policy_fingerprint':m.fingerprint(policy),'original_users_sha256':m.fingerprint(snapshot['users'])}
    m.retired_user_ids(result)
    return result


def retire(k,snapshot,confirmed_users,save_backup):
    """Delete only exact confirmed UUIDs after a durable private backup callback.

    Args:
        k (callable): Authenticated Keycloak Admin API client.
        snapshot (dict): Verified original migration snapshot with legacy rows.
        confirmed_users (list[str]): Exact usernames approved for this operation.
        save_backup (callable): Persist backup dict and candidate baseline; must
            raise on failure. Called before any remote write, never after one.
    Returns:
        tuple[dict, dict]: Readback result and new verification snapshot.
    Raises:
        ValueError: Confirmation, identity, or active guarded configuration drift.
        Exception: Backup/API/readback failure. No automatic destructive retry
            or user recreation; inspect candidate baseline after uncertain writes.
    """
    candidate=retired_snapshot(snapshot)
    names=sorted(x['user']['username'] for x in snapshot['users'])
    m.need(sorted(confirmed_users)==names and len(set(names))==len(names))
    sso.verify(k,snapshot,True)
    root='/admin/realms/'+snapshot['policy']['realm']
    details={}
    for old in snapshot['users']:
        path=root+'/users/'+old['user']['id']
        details[old['user']['id']]={name:k(path+'/'+name) for name in ('credentials','groups','role-mappings')}
    save_backup({'snapshot':copy.deepcopy(snapshot),'candidate_snapshot':candidate,
        'current_realm':k(root),'user_details':details,
        'warning':'No password values or session backup; no automatic legacy UUID restoration'})
    # Re-read exact records after backup; never replace UUID targeting with name search.
    m.need(k(root+'/users/count')==len(snapshot['users']))
    for old in snapshot['users']:
        path=root+'/users/'+old['user']['id']
        m.need(k(path)==old['user'] and k(path+'/federated-identity')==old['links'])
    for old in snapshot['users']:k(root+'/users/'+old['user']['id'],'DELETE')
    result=sso.verify(k,candidate,True)
    return result|{'deleted_persistent_users':len(names),'aws_quick_writes':False},candidate

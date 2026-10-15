#!/usr/bin/env python3
"""Build an explicit allowlisted delivery archive; never include customer data."""
import argparse
from pathlib import Path
import zipfile

VERSION = '1.0.0'
PREFIX = 'quick-wecom-transient-sso/'
FILES = (
    ".github/workflows/checks.yml",
    ".gitignore",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "community-provider/.dockerignore",
    "community-provider/Dockerfile",
    "community-provider/upstream.lock.json",
    "docs/完整手动配置图文说明.md",
    "docs/已有环境扫码接入.md",
    "docs/扫码登录快速实施.md",
    "docs/方案与参数.md",
    "docs/管理员映射临时用户实施.md",
    "docs/项目维护.md",
    "docs/首次部署权限与恢复.md",
    "mapped-provider/.dockerignore",
    "mapped-provider/Dockerfile",
    "mapped-provider/pom.xml",
    "mapped-provider/src/main/java/services/quickwecom/MappedCookieAuthenticator.java",
    "mapped-provider/src/main/java/services/quickwecom/MappedPolicy.java",
    "mapped-provider/src/main/java/services/quickwecom/MappedSessionApproval.java",
    "mapped-provider/src/main/java/services/quickwecom/MappedTransientMapper.java",
    "mapped-provider/src/main/resources/META-INF/services/org.keycloak.authentication.AuthenticatorFactory",
    "mapped-provider/src/main/resources/META-INF/services/org.keycloak.broker.provider.IdentityProviderMapper",
    "mapped-provider/src/test/java/services/quickwecom/MappedPolicyTest.java",
    "mapped-provider/src/test/java/services/quickwecom/MappedSessionApprovalTest.java",
    "mapped_cleanup.py",
    "mapped_sso.py",
    "mapped_transient.py",
    "new-customer.example.json",
    "new_customer.py",
    "package-lock.json",
    "package.json",
    "requirements.txt",
    "scripts/migrate_mapped_sso.py",
    "scripts/migrate_mapped_transient.py",
    "scripts/package_sso.py",
    "scripts/protocol_test_support.py",
    "scripts/render-runbook.mjs",
    "scripts/retire_mapped_users.py",
    "scripts/test_mapped_transient_keycloak.py",
    "scripts/test_new_customer_local_keycloak.py",
    "scripts/verify_customer_delivery.mjs",
    "store_secret.py",
    "tests/__init__.py",
    "tests/test_mapped_cleanup.py",
    "tests/test_mapped_migration.py",
    "tests/test_mapped_sso.py",
    "tests/test_mapped_transient.py",
    "tests/test_new_customer.py",
    "tests/test_project.py",
    "tests/test_wecom_sso.py",
    "transient_flow.py",
    "wecom-sso.example.json",
    "wecom_sso.py",
)
# These individually reviewed screenshots match the prior published kit.
ASSETS = (
    "docs/screenshots/01-wecom-application.png",
    "docs/screenshots/02-wecom-features.png",
    "docs/screenshots/03-wecom-qr-domain.png",
    "docs/screenshots/05a-keycloak-desktop-general.png",
    "docs/screenshots/05b-keycloak-desktop-capabilities.png",
    "docs/screenshots/05c-keycloak-wecom.png",
    "docs/screenshots/05d-keycloak-tokens.png",
    "docs/screenshots/05e-keycloak-wecom-advanced.png",
    "docs/screenshots/06-quick-admin-navigation.png",
    "docs/screenshots/07-quick-extension-access-entry.png",
    "docs/screenshots/08-quick-extensions.png",
    "docs/screenshots/10-quick-sso-settings.png",
    "docs/screenshots/11-iam-saml-upload.png",
    "docs/screenshots/12-iam-role-arn.png",
    "docs/screenshots/13-manual-prelinked-flow.jpg",
    "docs/screenshots/14-manual-link-account.jpg",
    "docs/screenshots/15-manual-saml-settings.jpg",
    "docs/screenshots/16-manual-saml-mappers.jpg",
    "docs/screenshots/17-manual-saml-acs.jpg",
    "docs/screenshots/18-manual-saml-keys.jpg",
)
GENERATED = tuple(name[:-3]+'.html' for name in FILES if name.endswith('.md'))
BINARY = ('mapped-provider/target/quick-wecom-mapped-transient-1.1.0.jar',)


def release_files(root=None, include_html=False, include_binary=False):
    """Resolve only reviewed regular files, rejecting symlinks and missing entries."""
    root = Path(root or Path(__file__).resolve().parents[1])
    names = FILES + ASSETS + (GENERATED if include_html else ()) + (BINARY if include_binary else ())
    if len(set(names)) != len(names):
        raise ValueError('Duplicate release entry')
    result = []
    for name in names:
        relative = Path(name)
        file = root / relative
        if (relative.is_absolute() or '..' in relative.parts or not file.is_file()
                or any((root / parent).is_symlink() for parent in (relative, *relative.parents))):
            raise ValueError('Missing/unsafe allowlisted asset: ' + name)
        result.append(file)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--output', required=True, help='New ZIP filename; never overwritten')
    parser.add_argument('--source-only', action='store_true', help='Omit offline HTML and compiled JAR')
    parser.add_argument('--with-provider', action='store_true', help='Include the built mapped provider 1.1.0')
    args = parser.parse_args()
    if args.source_only and args.with_provider:
        parser.error('--source-only cannot include a compiled provider')
    root = Path(__file__).resolve().parents[1]
    try:
        files = release_files(root, include_html=not args.source_only, include_binary=args.with_provider)
    except ValueError as error:
        parser.error(str(error) + '; build HTML and, for --with-provider, build the mapped JAR first.')
    with zipfile.ZipFile(args.output, 'x', zipfile.ZIP_DEFLATED) as archive:
        for file in files:
            archive.write(file, PREFIX + file.relative_to(root).as_posix())
    print('Created ZIP with ' + str(len(files)) + ' allowlisted files.')


if __name__ == '__main__':
    main()

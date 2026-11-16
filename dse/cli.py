import argparse
import json
from pathlib import Path
import sys

from . import capsule, catalog, keys


def main(argv=None):
    parser = argparse.ArgumentParser(prog="dse", description="DSE local capsule development tools")
    parser.add_argument("--keyring", required=True, type=Path, help="private development key file")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("init", help="create a single-operator development keyring")
    actions.add_parser("identity", help="show the public tenant and signer IDs for provisioning")
    head = actions.add_parser("head", help="read the current version from Atlas")
    head.add_argument("--object", required=True)
    commit = actions.add_parser("commit", help="promote an existing local capsule in Atlas")
    commit.add_argument("--expect", required=True, metavar="VERSION|none",
                        help="expected current version, or none for the first write")
    seal = actions.add_parser("seal", help="publish one encrypted version")
    seal.add_argument("file", type=Path)
    seal.add_argument("--namespace", default="default")
    seal.add_argument("--object", help="reuse a logical object UUID")
    verify = actions.add_parser("verify", help="verify signature, ciphertext and authentication tags")
    restore = actions.add_parser("restore", help="restore to a new file")
    restore.add_argument("destination", type=Path)
    for action in [seal, verify, restore, commit]:
        action.add_argument("--store", type=Path, required=True)
    for action in [verify, restore, commit]:
        action.add_argument("--object", required=True)
        action.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "init":
            keys.initialize(args.keyring)
            result = {"tenant": keys.load(args.keyring).tenant}
        else:
            keyring = keys.load(args.keyring)
            if args.action == "seal":
                result = capsule.seal(args.file, args.store, keyring, args.namespace, args.object)
            elif args.action == "identity":
                result = {"tenant": keyring.tenant, "signer_id": keyring.signer_id}
            elif args.action == "head":
                result = catalog.head(keyring, args.object)
            elif args.action == "commit":
                result = catalog.commit(args.store, keyring, args.object, args.version, args.expect)
            else:
                result = capsule.recover(args.store, keyring, args.object, args.version,
                                         getattr(args, "destination", None))
        print(json.dumps(result))
        return 0
    except catalog.Conflict as exc:
        print(f"dse: {exc}", file=sys.stderr)
        return 3
    except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
        print(f"dse: {exc}", file=sys.stderr)
        return 1

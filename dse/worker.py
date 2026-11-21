"""Execute durable commit operations using the API's configured tenant identities."""
import argparse
import os
import sys
import time

from . import capsule, catalog, dcf, operations
from .access import Settings


def process_one(settings, principal, lease_seconds=300):
    job = operations.claim(principal, lease_seconds)
    if job is None:
        return False
    try:
        if not principal.allows("write", job["namespace"]):
            operations.fail(principal, job, "POLICY_DENIED")
            return True
        store = settings.store / principal.keyring.tenant
        manifest, wrapped = capsule.catalog_material(store, principal.keyring, job["object_id"], job["version_id"])
        if dcf.digest(dcf.canonical(manifest)).hex() != job["manifest_digest"]:
            raise dcf.InvalidData("Queued manifest changed")
        operations.complete(principal, job, manifest, wrapped, store)
    except catalog.LeaseLost:
        return True
    except catalog.Conflict:
        operations.fail(principal, job, "VERSION_CONFLICT")
    except FileNotFoundError:
        operations.fail(principal, job, "CAPSULE_MISSING")
    except (dcf.InvalidData, KeyError, TypeError):
        operations.fail(principal, job, "INTEGRITY_FAILURE")
    except (ValueError, OSError):
        operations.fail(principal, job, "TRANSIENT_STORAGE_ERROR", retry=True)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="DSE durable commit worker")
    parser.add_argument("--once", action="store_true", help="process at most one operation, then exit")
    parser.add_argument("--lease-seconds", type=int, default=300, choices=range(5, 3601), metavar="5..3600")
    args = parser.parse_args(argv)
    try:
        while True:
            settings = Settings.load(os.environ["DSE_API_CONFIG"])
            worked = False
            for principal in settings.principals:
                try:
                    if process_one(settings, principal, args.lease_seconds):
                        worked = True
                        if args.once:
                            return 0
                except (ValueError, OSError):
                    print("DSE worker database unavailable. Retrying.", file=sys.stderr)
                    if args.once:
                        return 1
            if args.once:
                return 0
            if not worked:
                time.sleep(1)
    except KeyboardInterrupt:
        return 0
    except (ValueError, OSError, KeyError):
        print("DSE worker stopped. Check configuration and database availability.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

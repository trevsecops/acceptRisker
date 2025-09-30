import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
from tenable.sc import TenableSC
from tenable.errors import APIError

# -----------------------------
# CONFIG
# -----------------------------
TENABLE_SC_URL = os.getenv("TENABLE_SC_URL", "https://tenable_admin.sce.com")
ACCESS_KEY     = os.getenv("TENABLE_SC_ACCESS_KEY") or "REPLACE_ME"
SECRET_KEY     = os.getenv("TENABLE_SC_SECRET_KEY") or "REPLACE_ME"

PLUGIN_NAME_PATTERN = "Linux Distros Unpatched Vulnerability"  # 'like' search
REPO_ID = 5                                 # target repository ID
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"  # set to "true" to test without creating

LOG_PATH = os.getenv("LOG_PATH", "tenable_accept_risk.log")

# -----------------------------
# LOGGING
# -----------------------------
logger = logging.getLogger("auto_accept_linux_unpatched")
logger.setLevel(logging.DEBUG)

# Rotating file log (5 MB x 5)
fh = RotatingFileHandler(LOG_PATH, maxBytes=5*1024*1024, backupCount=5)
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

# Console
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

logger.addHandler(fh)
logger.addHandler(ch)

def connect_sc():
    """Login to Tenable.sc."""
    logger.info("Connecting to Tenable.sc at %s", TENABLE_SC_URL)
    sc = TenableSC(TENABLE_SC_URL)
    sc.login(access_key=ACCESS_KEY, secret_key=SECRET_KEY)
    logger.info("Connected successfully.")
    return sc

def fetch_target_plugins(sc):
    """
    Retrieve plugins whose names contain PLUGIN_NAME_PATTERN.
    Uses sc.plugins.list(filter=('name','like',pattern)).
    """
    logger.info("Querying plugins with name like '%s' ...", PLUGIN_NAME_PATTERN)
    plugins_iter = sc.plugins.list(
        fields=['id', 'name', 'pluginPubDate', 'pluginModDate'],
        filter=('name', 'like', PLUGIN_NAME_PATTERN)
    )
    plugins = []
    for p in plugins_iter:
        try:
            pid = int(p.get('id'))
            pname = p.get('name', '')
            plugins.append({'id': pid, 'name': pname})
        except Exception as e:
            logger.warning("Skipping malformed plugin record %s: %s", p, e)
    logger.info("Found %d matching plugins.", len(plugins))
    return plugins

def existing_rule_for(sc, repo_id, plugin_id):
    """
    Check if an Accept Risk rule already exists for this repo & plugin.
    Uses sc.accept_risks.list(repo_ids=[repo_id], plugin_id=plugin_id)
    """
    rules = sc.accept_risks.list(repo_ids=[repo_id], plugin_id=plugin_id)
    # Some environments return list[dict] where each has keys including 'repositories' or 'repos'
    has_match = len(rules) > 0
    logger.debug("Existing rules for plugin %s in repo %s: %d", plugin_id, repo_id, len(rules))
    return has_match, rules

def create_rule(sc, repo_id, plugin_id, comment):
    """
    Create an Accept Risk rule restricted to the repo (all IPs in that repo).
    Per docs: create(plugin_id, repos=[repo_id], <optional params>).
    """
    if DRY_RUN:
        logger.info("[DRY-RUN] Would create Accept Risk rule for plugin %s in repo %s", plugin_id, repo_id)
        return None

    logger.info("Creating Accept Risk rule for plugin %s in repo %s ...", plugin_id, repo_id)
    rule = sc.accept_risks.create(plugin_id, [repo_id], comments=comment)
    logger.info("Created rule id=%s for plugin %s", rule.get('id'), plugin_id)
    return rule

def main():
    start = time.time()
    created = 0
    observed = 0
    skipped_existing = 0
    failures = 0
    created_rule_ids = []

    try:
        sc = connect_sc()
    except Exception as e:
        logger.exception("Failed to connect/login to Tenable.sc: %s", e)
        sys.exit(2)

    try:
        plugins = fetch_target_plugins(sc)
        observed = len(plugins)

        for pl in plugins:
            pid, pname = pl['id'], pl['name']
            logger.debug("Evaluating plugin id=%s name=%s", pid, pname)

            try:
                exists, rules = existing_rule_for(sc, REPO_ID, pid)
            except APIError as e:
                failures += 1
                logger.error("Error checking existing rules for plugin %s: %s", pid, e)
                continue

            if exists:
                skipped_existing += 1
                logger.info("Rule already exists for plugin %s (%s) in repo %s; skipping.",
                            pid, pname, REPO_ID)
                continue

            # Create a new rule (all IPs in the repo)
            comment = f"Automated risk acceptance for plugin {pid} - '{pname}' (repo {REPO_ID})"
            try:
                rule = create_rule(sc, REPO_ID, pid, comment)
                if rule and rule.get('id'):
                    created_rule_ids.append(rule['id'])
                    created += 1
            except APIError as e:
                failures += 1
                logger.error("Failed to create rule for plugin %s: %s", pid, e)

    finally:
        try:
            sc.logout()
            logger.info("Logged out of Tenable.sc.")
        except Exception:
            pass

    elapsed = time.time() - start
    logger.info("SUMMARY: observed=%d, created=%d, already-existed=%d, failures=%d, seconds=%.2f",
                observed, created, skipped_existing, failures, elapsed)
    if created_rule_ids:
        logger.debug("Created rule IDs: %s", created_rule_ids)

if __name__ == "__main__":
    main()

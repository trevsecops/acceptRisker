import time
import logging
from tenable.sc import TenableSC
from tenable.errors import APIError

# -----------------------------------------------------------------------------
# LOGGING CONFIGURATION
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("asset_creation.log"),   # detailed log file
        logging.StreamHandler()                      # console output
    ]
)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# TENABLE.SC CONNECTION (static style)
# -----------------------------------------------------------------------------
a_key = "078f9ac50b734a0b89c3558fc398ab90"
s_key = "79ace1cc876f4870b43d34c24cee9984"
tenable_sc_url = "tenable_admin.sce.com"

# -----------------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------------
PLUGIN_NAME_PATTERN = "Linux Distros Unpatched Vulnerability"
REPO_ID = 5
DRY_RUN = False                # set True to log only, no changes
DEBUG_SINGLE_PLUGIN_ID = None  # e.g. 231722 for testing single plugin


def connect_sc():
    """Login to Tenable.sc."""
    logger.info("Connecting to Tenable.sc at %s", tenable_sc_url)
    sc = TenableSC(tenable_sc_url)
    sc.login(access_key=a_key, secret_key=s_key)
    logger.info("Connected successfully.")
    return sc


def fetch_target_plugins(sc):
    """
    Retrieve target plugins. If DEBUG_SINGLE_PLUGIN_ID is set,
    only return that plugin. Otherwise, search by name pattern.
    """
    if DEBUG_SINGLE_PLUGIN_ID:
        logger.warning("====================================================")
        logger.warning(" RUNNING IN DEBUG MODE: ONLY PROCESSING PLUGIN ID %s ", DEBUG_SINGLE_PLUGIN_ID)
        logger.warning("====================================================")
        try:
            plugin = sc.plugins.details(int(DEBUG_SINGLE_PLUGIN_ID))
            return [{'id': int(plugin['id']), 'name': plugin.get('name', '')}]
        except Exception as e:
            logger.error("Failed to fetch plugin id=%s: %s", DEBUG_SINGLE_PLUGIN_ID, e)
            return []

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
    """
    rules = sc.accept_risks.list(repo_ids=[repo_id], plugin_id=plugin_id)
    has_match = len(rules) > 0
    logger.debug("Existing rules for plugin %s in repo %s: %d", plugin_id, repo_id, len(rules))
    return has_match, rules


def create_rule(sc, repo_id, plugin_id, comment):
    """Create an Accept Risk rule restricted to the repo."""
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
        return

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

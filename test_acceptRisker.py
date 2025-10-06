import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenable.sc import TenableSC
from tenable.errors import APIError

# ----------------------------------------------------------------------------- #
# LOGGING CONFIGURATION
# ----------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("rule_creation.log"),   # detailed log file
        logging.StreamHandler()                     # console output
    ]
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------- #
# TENABLE.SC CONNECTION (static style)
# ----------------------------------------------------------------------------- #
a_key = "078f9ac50b734a0b89c3558fc398ab90"
s_key = "79ace1cc876f4870b43d34c24cee9984"
tenable_sc_url = "tenable_admin.sce.com"

# ----------------------------------------------------------------------------- #
# CONFIGURATION
# ----------------------------------------------------------------------------- #
PLUGIN_NAME_PATTERN = "Unpatched"
REPO_ID = 5
DRY_RUN = False                # set True to log only, no changes
DEBUG_SINGLE_PLUGIN_ID = None  # e.g. 231722 for testing single plugin
MAX_WORKERS = 5                # number of threads
THREAD_START_DELAY = 0.5       # seconds delay between thread spawns (rate limiter)


# ----------------------------------------------------------------------------- #
# CONNECTION / API HELPERS
# ----------------------------------------------------------------------------- #
def connect_sc():
    """Login to Tenable.sc."""
    sc = TenableSC(tenable_sc_url)
    sc.login(access_key=a_key, secret_key=s_key)
    return sc


def fetch_target_plugins(sc):
    """Retrieve target plugins."""
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
    """Check if an Accept Risk rule already exists for this repo & plugin."""
    rules = sc.accept_risks.list(repo_ids=[repo_id], plugin_id=plugin_id)
    has_match = len(rules) > 0
    return has_match, rules


def create_rule(sc, repo_id, plugin_id, comment):
    """Create an Accept Risk rule restricted to the repo."""
    rule = sc.accept_risks.create(plugin_id, [repo_id], comments=comment)
    return rule


# ----------------------------------------------------------------------------- #
# THREAD WORKER
# ----------------------------------------------------------------------------- #
def process_plugin(plugin):
    """
    Worker function for each plugin.
    Creates its own SC connection for thread safety.
    Returns a tuple: (plugin_id, created?, message)
    """
    pid, pname = plugin['id'], plugin['name']
    try:
        sc = connect_sc()
        exists, _ = existing_rule_for(sc, REPO_ID, pid)
        if exists:
            msg = f"Rule already exists for plugin {pid} ({pname}) in repo {REPO_ID}"
            logger.info(msg)
            return pid, False, msg

        comment = f"Automated risk acceptance for plugin {pid} - '{pname}' (repo {REPO_ID})"
        if DRY_RUN:
            msg = f"[DRY-RUN] Would create Accept Risk rule for plugin {pid} in repo {REPO_ID}"
            logger.info(msg)
            return pid, False, msg

        rule = create_rule(sc, REPO_ID, pid, comment)
        msg = f"Created rule id={rule.get('id')} for plugin {pid}"
        logger.info(msg)
        return pid, True, msg
    except APIError as e:
        msg = f"APIError for plugin {pid}: {e}"
        logger.error(msg)
        return pid, False, msg
    except Exception as e:
        msg = f"Error processing plugin {pid}: {e}"
        logger.exception(msg)
        return pid, False, msg
    finally:
        try:
            sc.logout()
        except Exception:
            pass


# ----------------------------------------------------------------------------- #
# MAIN EXECUTION
# ----------------------------------------------------------------------------- #
def main():
    start = time.time()
    created = 0
    skipped_existing = 0
    failures = 0

    sc = None
    try:
        sc = connect_sc()
        logger.info("Connected successfully to Tenable.sc at %s", tenable_sc_url)
        plugins = fetch_target_plugins(sc)
    finally:
        if sc:
            sc.logout()

    if not plugins:
        logger.warning("No plugins found to process.")
        return

    logger.info("Starting threaded processing with %d workers...", MAX_WORKERS)
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for idx, plugin in enumerate(plugins):
            futures.append(executor.submit(process_plugin, plugin))
            # Small delay to prevent login bursts
            if idx < len(plugins) - 1:
                time.sleep(THREAD_START_DELAY)

        for future in as_completed(futures):
            pid, created_flag, msg = future.result()
            results.append((pid, created_flag, msg))
            if created_flag:
                created += 1
            elif "already exists" in msg:
                skipped_existing += 1
            else:
                failures += 1

    elapsed = time.time() - start
    logger.info(
        "SUMMARY: observed=%d, created=%d, already-existed=%d, failures=%d, seconds=%.2f",
        len(plugins), created, skipped_existing, failures, elapsed
    )


if __name__ == "__main__":
    main()
